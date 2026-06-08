#pragma once

#include <stdint.h>

/* Binary capture record sent over the console UART for Wireshark extcap.
 * Layout: magic(2) version(1) channel(1) rssi(1) lqi(1) timestamp_us(8) len(1) psdu[len]
 * PSDU is the 802.15.4 MAC frame (MHR + payload), without PHR length byte, without FCS,
 * and without the two ESP driver RSSI/LQI bytes that replace FCS in the RX buffer.
 */
#define SNIFF_MAGIC0           'Z'
#define SNIFF_MAGIC1           'S'
#define SNIFF_PROTO_VERSION    1
#define SNIFF_MAX_PSDU_LEN     127
#define SNIFF_RECORD_HDR_SIZE  15

#pragma pack(push, 1)
typedef struct {
    uint8_t magic0;
    uint8_t magic1;
    uint8_t version;
    uint8_t channel;
    int8_t rssi;
    uint8_t lqi;
    uint64_t timestamp_us;
    uint8_t len;
} sniff_record_hdr_t;
#pragma pack(pop)
