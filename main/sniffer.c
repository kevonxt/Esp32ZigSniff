#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/portmacro.h"
#include "esp_check.h"
#include "esp_ieee802154.h"
#include "esp_ieee802154_types.h"
#include "esp_log.h"
#include "esp_attr.h"
#include "nvs_flash.h"
#include "sniff_protocol.h"

static const char *TAG = "i154_sniffer";

#define FIRST_ZB_CHANNEL 11
#define LAST_ZB_CHANNEL 26
#define CHANNEL_DWELL_MS 1200
#define REPORT_INTERVAL_MS 3000
#define SNIFF_FRAME_QUEUE_LEN 32

typedef struct {
    uint8_t channel;
    int8_t rssi;
    uint8_t lqi;
    uint64_t timestamp_us;
    uint8_t len;
    uint8_t psdu[SNIFF_MAX_PSDU_LEN];
} sniff_queued_frame_t;

static volatile uint32_t s_channel_hits[LAST_ZB_CHANNEL + 1];
static volatile uint32_t s_total_frames;
static volatile uint32_t s_dropped_frames;
static volatile uint8_t s_current_channel = FIRST_ZB_CHANNEL;
static volatile uint8_t s_manual_channel = FIRST_ZB_CHANNEL;
static volatile bool s_scan_enabled = true;
static volatile bool s_wireshark_mode = false;
static portMUX_TYPE s_stats_mux = portMUX_INITIALIZER_UNLOCKED;
static QueueHandle_t s_frame_queue;

#define LOGI_IF_CLI(...) do { if (!s_wireshark_mode) { ESP_LOGI(TAG, __VA_ARGS__); } } while (0)
#define LOGW_IF_CLI(...) do { if (!s_wireshark_mode) { ESP_LOGW(TAG, __VA_ARGS__); } } while (0)

static inline bool is_valid_zb_channel(uint8_t ch)
{
    return ch >= FIRST_ZB_CHANNEL && ch <= LAST_ZB_CHANNEL;
}

static void enqueue_frame(uint8_t *frame, esp_ieee802154_frame_info_t *info)
{
    /* frame[0] spans MHR+payload plus two bytes where FCS was replaced by RSSI/LQI
     * (see ieee802154_rx_frame_info_update() in esp_ieee802154_dev.c). */
    uint8_t phr_len = frame[0];
    if (phr_len < 3 || phr_len > SNIFF_MAX_PSDU_LEN) {
        return;
    }
    uint8_t mac_len = phr_len - 2;

    sniff_queued_frame_t queued = {
        .channel = info->channel,
        .rssi = info->rssi,
        .lqi = info->lqi,
        .timestamp_us = info->timestamp,
        .len = mac_len,
    };
    memcpy(queued.psdu, frame + 1, mac_len);

    BaseType_t hp_task = pdFALSE;
    if (xQueueSendFromISR(s_frame_queue, &queued, &hp_task) != pdTRUE) {
        portENTER_CRITICAL_ISR(&s_stats_mux);
        s_dropped_frames++;
        portEXIT_CRITICAL_ISR(&s_stats_mux);
    } else if (hp_task == pdTRUE) {
        portYIELD_FROM_ISR();
    }
}

// Called from 802.15.4 RX context; keep this short and non-blocking.
void IRAM_ATTR esp_ieee802154_receive_done(uint8_t *frame, esp_ieee802154_frame_info_t *info)
{
    if (is_valid_zb_channel(info->channel)) {
        portENTER_CRITICAL_ISR(&s_stats_mux);
        s_channel_hits[info->channel]++;
        s_total_frames++;
        portEXIT_CRITICAL_ISR(&s_stats_mux);
    }

    enqueue_frame(frame, info);

    esp_ieee802154_receive_handle_done(frame);
    esp_ieee802154_receive();
}

static void export_task(void *arg)
{
    (void)arg;
    uint8_t out_buf[SNIFF_RECORD_HDR_SIZE + SNIFF_MAX_PSDU_LEN];

    while (true) {
        sniff_queued_frame_t frame;
        if (xQueueReceive(s_frame_queue, &frame, portMAX_DELAY) != pdTRUE) {
            continue;
        }

        sniff_record_hdr_t hdr = {
            .magic0 = SNIFF_MAGIC0,
            .magic1 = SNIFF_MAGIC1,
            .version = SNIFF_PROTO_VERSION,
            .channel = frame.channel,
            .rssi = frame.rssi,
            .lqi = frame.lqi,
            .timestamp_us = frame.timestamp_us,
            .len = frame.len,
        };

        memcpy(out_buf, &hdr, sizeof(hdr));
        memcpy(out_buf + sizeof(hdr), frame.psdu, frame.len);

        size_t total = sizeof(hdr) + frame.len;
        ssize_t written = write(STDOUT_FILENO, out_buf, total);
        if (!s_wireshark_mode && (written < 0 || (size_t)written != total)) {
            ESP_LOGW(TAG, "export write failed (%d of %u bytes)", (int)written, (unsigned)total);
        }
    }
}

static void channel_hopper_task(void *arg)
{
    (void)arg;
    uint8_t ch = FIRST_ZB_CHANNEL;

    while (true) {
        uint8_t target_ch;
        if (s_scan_enabled) {
            target_ch = ch;
            ch++;
            if (ch > LAST_ZB_CHANNEL) {
                ch = FIRST_ZB_CHANNEL;
            }
        } else {
            target_ch = s_manual_channel;
            ch = target_ch;
        }

        ESP_ERROR_CHECK(esp_ieee802154_set_channel(target_ch));
        s_current_channel = target_ch;

        esp_err_t rx_err = esp_ieee802154_receive();
        if (rx_err != ESP_OK && rx_err != ESP_ERR_INVALID_STATE) {
            ESP_ERROR_CHECK(rx_err);
        }

        vTaskDelay(pdMS_TO_TICKS(CHANNEL_DWELL_MS));
    }
}

static void stats_task(void *arg)
{
    (void)arg;
    uint32_t last_total = 0;

    while (true) {
        vTaskDelay(pdMS_TO_TICKS(REPORT_INTERVAL_MS));

        uint32_t total_now;
        uint32_t dropped_now;
        uint32_t best_hits = 0;
        uint8_t best_ch = FIRST_ZB_CHANNEL;

        portENTER_CRITICAL(&s_stats_mux);
        total_now = s_total_frames;
        dropped_now = s_dropped_frames;
        for (uint8_t ch = FIRST_ZB_CHANNEL; ch <= LAST_ZB_CHANNEL; ch++) {
            uint32_t hits = s_channel_hits[ch];
            if (hits > best_hits) {
                best_hits = hits;
                best_ch = ch;
            }
        }
        portEXIT_CRITICAL(&s_stats_mux);

        ESP_LOGD(TAG,
                 "rx_total=%lu (+%lu/%ums) dropped=%lu current_ch=%u busiest_ch=%u hits=%lu",
                 (unsigned long)total_now,
                 (unsigned long)(total_now - last_total),
                 REPORT_INTERVAL_MS,
                 (unsigned long)dropped_now,
                 s_current_channel,
                 best_ch,
                 (unsigned long)best_hits);
        last_total = total_now;
    }
}

static void print_help(void)
{
    printf("\nCommands:\n");
    printf("  help            - show this help\n");
    printf("  status          - show current mode/channel\n");
    printf("  scan on|off     - enable/disable channel scan\n");
    printf("  ch <11..26>     - set manual channel and disable scan\n");
    printf("  next            - next manual channel\n");
    printf("  prev            - previous manual channel\n");
    printf("  lock busiest    - switch to busiest seen channel\n");
    printf("  wireshark on|off- silence logs for Wireshark capture\n\n");
}

static void apply_manual_channel(uint8_t ch)
{
    if (!is_valid_zb_channel(ch)) {
        LOGW_IF_CLI("Invalid channel %u (valid: %u..%u)", ch, FIRST_ZB_CHANNEL, LAST_ZB_CHANNEL);
        return;
    }
    s_manual_channel = ch;
    s_scan_enabled = false;
    LOGI_IF_CLI("Manual mode enabled, target channel=%u", s_manual_channel);
}

static void lock_busiest_channel(void)
{
    uint32_t best_hits = 0;
    uint8_t best_ch = FIRST_ZB_CHANNEL;

    portENTER_CRITICAL(&s_stats_mux);
    for (uint8_t ch = FIRST_ZB_CHANNEL; ch <= LAST_ZB_CHANNEL; ch++) {
        uint32_t hits = s_channel_hits[ch];
        if (hits > best_hits) {
            best_hits = hits;
            best_ch = ch;
        }
    }
    portEXIT_CRITICAL(&s_stats_mux);

    if (best_hits == 0) {
        LOGW_IF_CLI("No frames counted yet; cannot lock busiest channel");
        return;
    }

    s_manual_channel = best_ch;
    s_scan_enabled = false;
    LOGI_IF_CLI("Locked to busiest channel=%u (hits=%lu)",
                best_ch, (unsigned long)best_hits);
}

static void cli_task(void *arg)
{
    (void)arg;
    char line[64];
    size_t idx = 0;

    while (true) {
        int c = getchar();
        if (c < 0) {
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }

        if (c == '\r' || c == '\n') {
            line[idx] = '\0';
            idx = 0;

            if (strlen(line) == 0) {
                continue;
            } else if (strcmp(line, "wireshark on") == 0) {
                s_wireshark_mode = true;
                esp_log_level_set("*", ESP_LOG_NONE);
            } else if (strcmp(line, "wireshark off") == 0) {
                s_wireshark_mode = false;
                esp_log_level_set("*", ESP_LOG_INFO);
            } else if (strcmp(line, "help") == 0) {
                print_help();
            } else if (strcmp(line, "status") == 0) {
                LOGI_IF_CLI("mode=%s current_ch=%u manual_ch=%u wireshark=%s",
                            s_scan_enabled ? "scan" : "manual",
                            s_current_channel, s_manual_channel,
                            s_wireshark_mode ? "on" : "off");
            } else if (strcmp(line, "scan on") == 0) {
                s_scan_enabled = true;
                LOGI_IF_CLI("Scan mode enabled");
            } else if (strcmp(line, "scan off") == 0) {
                s_scan_enabled = false;
                LOGI_IF_CLI("Scan mode disabled, staying on manual channel %u", s_manual_channel);
            } else if (strcmp(line, "next") == 0) {
                uint8_t next = s_manual_channel + 1;
                if (next > LAST_ZB_CHANNEL) {
                    next = FIRST_ZB_CHANNEL;
                }
                apply_manual_channel(next);
            } else if (strcmp(line, "prev") == 0) {
                uint8_t prev = s_manual_channel - 1;
                if (prev < FIRST_ZB_CHANNEL) {
                    prev = LAST_ZB_CHANNEL;
                }
                apply_manual_channel(prev);
            } else if (strncmp(line, "ch ", 3) == 0) {
                int ch = atoi(&line[3]);
                apply_manual_channel((uint8_t)ch);
            } else if (strcmp(line, "lock busiest") == 0) {
                lock_busiest_channel();
            } else {
                LOGW_IF_CLI("Unknown command: '%s' (type 'help')", line);
            }
            continue;
        }

        if (idx < (sizeof(line) - 1)) {
            line[idx++] = (char)c;
        } else {
            idx = 0;
            LOGW_IF_CLI("Input too long, line cleared");
        }
    }
}

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    s_frame_queue = xQueueCreate(SNIFF_FRAME_QUEUE_LEN, sizeof(sniff_queued_frame_t));
    ESP_ERROR_CHECK(s_frame_queue ? ESP_OK : ESP_ERR_NO_MEM);

    ESP_ERROR_CHECK(esp_ieee802154_enable());
    ESP_ERROR_CHECK(esp_ieee802154_set_promiscuous(true));
    ESP_ERROR_CHECK(esp_ieee802154_set_rx_when_idle(true));
    ESP_ERROR_CHECK(esp_ieee802154_set_channel(FIRST_ZB_CHANNEL));
    esp_log_level_set("*", ESP_LOG_WARN);

    ESP_LOGI(TAG, "ZS capture v%u ready. Wireshark: extcap sends 'wireshark on'. CLI: type 'help'",
             SNIFF_PROTO_VERSION);

    ESP_ERROR_CHECK(esp_ieee802154_receive());

    xTaskCreate(export_task, "i154_export", 4096, NULL, 6, NULL);
    xTaskCreate(channel_hopper_task, "i154_hop", 3072, NULL, 5, NULL);
    xTaskCreate(stats_task, "i154_stats", 3072, NULL, 5, NULL);
    xTaskCreate(cli_task, "i154_cli", 4096, NULL, 4, NULL);
}
