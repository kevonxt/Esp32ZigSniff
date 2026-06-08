# Esp32ZigSniff

Passive **IEEE 802.15.4** sniffer for **ESP32-C6** (ESP-IDF) with **Wireshark** live capture via an extcap plugin.  
Designed for Zigbee traffic on 2.4 GHz channels 11–26 in promiscuous mode.

```
ESP32-C6  --USB-->  extcap (Python)  --PCAP FIFO-->  Wireshark
                         ^
                    ZS binary protocol on serial
```

## Features

- Promiscuous RX on all Zigbee channels (11–26) with optional channel hopping
- Binary `ZS` capture protocol with per-frame channel, RSSI, LQI, and timestamp
- Wireshark extcap with **IEEE 802.15.4 TAP** (DLT 283) metadata
- Interactive serial CLI for manual channel control and debugging
- Silent capture mode (`wireshark on`) to keep the serial stream clean for Wireshark

## Hardware

| Board | Connection | Port (Linux) |
|-------|------------|----------------|
| ESP32-C6-DevKitC (USB-C) | Native USB Serial/JTAG | `/dev/ttyACM0` |
| Custom board + CP2102/CH340 | External USB-UART on UART0 | `/dev/ttyUSB0` |

Use the **on-board USB port** on DevKitC boards, not an external UART adapter, unless you wired UART0 yourself.

## Requirements

- [ESP-IDF](https://docs.espressif.com/projects/esp-idf/) **v5.1+** (tested with **5.3.2**)
- ESP32-C6 module or dev board
- Wireshark **4.x** recommended
- Python **3.8+** with `pyserial`

## Quick start

### 1. Build and flash firmware

```bash
idf.py set-target esp32c6
idf.py build
idf.py -p /dev/ttyACM0 flash
```

Do **not** run `idf.py monitor` while Wireshark is capturing — the extcap plugin needs exclusive access to the serial port.

### 2. Install Wireshark extcap

```bash
pip install -r tools/esp32c6_zigsniff/requirements.txt
chmod +x tools/esp32c6_zigsniff/install.sh
./tools/esp32c6_zigsniff/install.sh
```

Restart Wireshark or press **F5** (Refresh Interfaces).

### 3. Capture in Wireshark

1. Connect the ESP32-C6 via USB.
2. Select **ESP32-C6 802.15.4 Sniffer** → your port (e.g. `/dev/ttyACM0`).
3. Options:
   - **Channel**: 11–26 (default 15)
   - **Scan mode**: **Fixed channel** (recommended for Zigbee)
   - **Baud rate**: 115200 (ignored for USB Serial/JTAG)
4. Start capture.

Wireshark decodes 802.15.4 and Zigbee automatically. **Encrypted** Zigbee payloads require keys in Wireshark preferences (Zigbee → Pre-configured keys).

### Manual PCAP (without Wireshark UI)

```bash
python3 tools/esp32c6_zigsniff/extcap_esp32c6_zigsniff.py \
  --capture --extcap-interface /dev/ttyACM0 \
  --channel 15 --scan off -o capture.pcap
```

Press `Ctrl+C` to stop.

## Project layout

```
Esp32ZigSniff/
├── CMakeLists.txt
├── sdkconfig.defaults      # Target and console defaults
├── sdkconfig               # Full IDF configuration (committed)
├── main/
│   ├── sniffer.c           # Sniffer firmware
│   └── sniff_protocol.h    # ZS binary protocol definition
└── tools/esp32c6_zigsniff/
    ├── extcap_esp32c6_zigsniff.py   # Wireshark extcap plugin
    ├── install.sh                   # Installs extcap for current user
    └── requirements.txt
```

## Serial CLI

Available via `idf.py -p PORT monitor` when not capturing in Wireshark:

| Command | Description |
|---------|-------------|
| `help` | Show command list |
| `status` | Current mode, channel, wireshark state |
| `scan on` / `scan off` | Enable/disable channel hopping (11–26) |
| `ch 15` | Lock to channel 15 (disables scan) |
| `next` / `prev` | Step through channels in manual mode |
| `lock busiest` | Lock to the channel with the most received frames |
| `wireshark on` / `wireshark off` | Silence logs for clean Wireshark capture |

The extcap plugin sends `wireshark on`, `scan off`, and `ch N` automatically when capture starts with **Fixed channel** mode.

## Binary capture protocol (`ZS`)

Each received 802.15.4 frame is emitted as one binary record on the USB serial port:

| Field | Size | Description |
|-------|------|-------------|
| Magic | 2 | `Z` `S` |
| Version | 1 | `1` |
| Channel | 1 | 11–26 |
| RSSI | 1 | signed dBm |
| LQI | 1 | link quality indicator |
| Timestamp | 8 | microseconds (ESP radio timestamp) |
| Length | 1 | MAC frame length |
| PSDU | N | 802.15.4 MAC header + payload |

**PSDU contents:** MHR + MAC payload only — no PHR length byte, no FCS, and no ESP driver RSSI/LQI trailer bytes (the driver replaces FCS with RSSI/LQI in the RX buffer; firmware strips them before export).

See `main/sniff_protocol.h` for the C structure.

The extcap plugin wraps PSDU in **IEEE 802.15.4 TAP** PCAP records (channel, RSSI, LQI in TLV headers).

## Configuration notes

- **Console:** USB Serial/JTAG (`CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG`) — required for CLI + capture on the same USB port.
- **Channel hopping:** default dwell ~1.2 s per channel (`CHANNEL_DWELL_MS` in `sniffer.c`). For a fixed Zigbee coordinator channel, use **Fixed channel** in Wireshark or `scan off` + `ch N`.
- **Flash size:** `sdkconfig` may show 2 MB; many C6 modules have 4–8 MB. Adjust under `idf.py menuconfig` → Serial flasher config if needed.

## Troubleshooting

### Wireshark freezes on capture

1. Reflash the latest firmware (`idf.py flash`) and reinstall extcap (`./tools/esp32c6_zigsniff/install.sh`).
2. Close `idf.py monitor` before starting Wireshark.
3. Use **Fixed channel**, not scan mode, when observing a known Zigbee network.
4. Ensure firmware includes the FCS strip fix (`mac_len = phr_len - 2` in `enqueue_frame()`).

### Flash fails: `No serial data received`

- **DevKit USB-C** → use `/dev/ttyACM0`, not `/dev/ttyUSB0`.
- **External CP2102** → hold **BOOT**, press **RST**, release **BOOT**, then flash.
- Try lower baud: `idf.py -p PORT -b 115200 flash`.

### Wrong or empty interfaces in Wireshark

- Only USB serial ports are listed (`ttyACM*`, `ttyUSB*`), not onboard `ttyS*`.
- Press **F5** after plugging in the board.
- Run `python3 tools/esp32c6_zigsniff/extcap_esp32c6_zigsniff.py --extcap-interfaces` to verify.

### No packets in Wireshark

- Confirm Zigbee traffic on the selected channel (`lock busiest` in monitor helps find the active channel).
- Move the sniffer closer to the coordinator or a active device.
- Check that `rx_total` increases in monitor (with `wireshark off`).

### Garbled output in `idf.py monitor`

Expected when capture is active — binary `ZS` records are mixed on the serial port. Use Wireshark for viewing frames, or `wireshark on` to suppress log spam.

## How it works

1. **Firmware** enables IEEE 802.15.4 promiscuous mode and receives all valid MAC frames.
2. The RX ISR queues frames; an export task writes `ZS` binary records to stdout/USB.
3. **extcap** reads the serial port, parses `ZS` records, and writes PCAP with IEEE 802.15.4 TAP headers to a FIFO.
4. **Wireshark** decodes 802.15.4 → Zigbee NWK/APS/ZCL when keys are available.

This sniffer operates at the **802.15.4 MAC layer** and does not require ZBOSS or Espressif's Zigbee stack.

## Publish to GitHub

```bash
cd Esp32ZigSniff
git init
git add .gitignore LICENSE README.md CMakeLists.txt sdkconfig sdkconfig.defaults main/ tools/
git commit -m "Initial commit: ESP32-C6 802.15.4 sniffer with Wireshark extcap"
git branch -M main
git remote add origin https://github.com/YOUR_USER/Esp32ZigSniff.git
git push -u origin main
```

The `build/` directory and local `*.pcap` files are excluded via `.gitignore`.

## License

MIT — see [LICENSE](LICENSE).
