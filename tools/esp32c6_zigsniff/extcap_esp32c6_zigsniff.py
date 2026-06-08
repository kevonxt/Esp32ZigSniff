#!/usr/bin/env python3
"""Wireshark extcap for the ESP32-C6 IEEE 802.15.4 sniffer."""

from __future__ import annotations

import argparse
import struct
import sys
import threading
import time
from dataclasses import dataclass
from enum import IntEnum
from queue import Empty, Full, Queue
from typing import BinaryIO, Optional

try:
    from serial import Serial
    from serial.tools.list_ports import comports
except ImportError:
    print("ERROR: pyserial is required (pip install pyserial)", file=sys.stderr)
    sys.exit(2)

SNIFF_MAGIC = b"ZS"
SNIFF_PROTO_VERSION = 1
SNIFF_RECORD_HDR_SIZE = 15
SNIFF_MAX_PSDU_LEN = 127

CTRL_LOGGER = 6
DEFAULT_BAUDRATE = 115200
ESPRESSIF_USB_VID = 0x303A
MAX_SERIAL_BUF = 8192
READ_SLICE_SEC = 0.05
QUEUE_GET_TIMEOUT_SEC = 0.1


class DLT(IntEnum):
    IEEE802_15_4_TAP = 283
    IEEE802_15_4_NOFCS = 230


@dataclass
class SnifferPacket:
    channel: int
    rssi: int
    lqi: int
    timestamp_us: int
    psdu: bytes


def tap_tlv(typ: int, data: bytes) -> bytes:
    buf = struct.pack("<HH", typ, len(data)) + data
    pad = (4 - (len(data) % 4)) % 4
    return buf + (b"\x00" * pad)


def build_tap_packet(channel: int, rssi: int, lqi: int, psdu: bytes) -> bytes:
    tlvs = b""
    tlvs += tap_tlv(0x0000, bytes([0]))
    tlvs += tap_tlv(0x0001, struct.pack("<f", float(rssi)))
    tlvs += tap_tlv(0x000A, bytes([lqi & 0xFF]))
    tlvs += tap_tlv(0x0003, struct.pack("<HB", channel, 0))
    header_len = 4 + len(tlvs)
    return struct.pack("<BBH", 0, 0, header_len) + tlvs + psdu


def pcap_global_header(dlt: int) -> bytes:
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, dlt)


def is_valid_psdu(psdu: bytes) -> bool:
    if len(psdu) < 3 or len(psdu) > SNIFF_MAX_PSDU_LEN:
        return False
    frame_type = psdu[0] & 0x07
    return frame_type <= 7


def drain_control_fifo(control_in: Optional[str]) -> None:
    if not control_in:
        return

    def _run() -> None:
        try:
            with open(control_in, "rb", buffering=0) as fifo:
                while True:
                    if not fifo.read(4096):
                        break
        except OSError:
            pass

    threading.Thread(target=_run, daemon=True, name="esp32c6-extcap-ctrl").start()


def pcap_packet(timestamp_us: int, payload: bytes) -> bytes:
    ts_sec = timestamp_us // 1_000_000
    ts_usec = timestamp_us % 1_000_000
    pkt_len = len(payload)
    return struct.pack("<IIII", ts_sec, ts_usec, pkt_len, pkt_len) + payload


class SerialFrameReader:
    """Parse ZS binary records from a byte stream that may contain ESP log noise."""

    def __init__(self, stream: BinaryIO) -> None:
        self.stream = stream
        self.buf = bytearray()

    def _timed_out(self, deadline: float) -> bool:
        return time.monotonic() >= deadline

    def _fill(self, deadline: float) -> bool:
        if self._timed_out(deadline):
            return False
        chunk = self.stream.read(512)
        if not chunk:
            return False
        self.buf.extend(chunk)
        if len(self.buf) > MAX_SERIAL_BUF:
            del self.buf[: len(self.buf) - MAX_SERIAL_BUF]
        return True

    def _discard_noise(self, deadline: float) -> bool:
        z = self.buf.find(ord("Z"))
        if z < 0:
            self.buf.clear()
        elif z > 0:
            del self.buf[:z]
        return self._fill(deadline)

    def read_packet(self, max_seconds: float = READ_SLICE_SEC) -> Optional[SnifferPacket]:
        deadline = time.monotonic() + max_seconds

        while not self._timed_out(deadline):
            while len(self.buf) < SNIFF_RECORD_HDR_SIZE:
                if not self._fill(deadline):
                    return None

            start = self.buf.find(SNIFF_MAGIC)
            if start < 0:
                if not self._discard_noise(deadline):
                    return None
                continue

            if start > 0:
                del self.buf[:start]

            if len(self.buf) < SNIFF_RECORD_HDR_SIZE:
                continue

            (
                magic0,
                magic1,
                version,
                channel,
                rssi,
                lqi,
                timestamp_us,
                psdu_len,
            ) = struct.unpack_from("<BBBBbBQB", self.buf, 0)

            if magic0 != ord("Z") or magic1 != ord("S"):
                del self.buf[0]
                continue

            if version != SNIFF_PROTO_VERSION or psdu_len == 0 or psdu_len > SNIFF_MAX_PSDU_LEN:
                del self.buf[0]
                continue

            total_len = SNIFF_RECORD_HDR_SIZE + psdu_len
            while len(self.buf) < total_len:
                if not self._fill(deadline):
                    return None

            psdu = bytes(self.buf[SNIFF_RECORD_HDR_SIZE:total_len])
            del self.buf[:total_len]
            return SnifferPacket(
                channel=channel,
                rssi=rssi,
                lqi=lqi,
                timestamp_us=timestamp_us,
                psdu=psdu,
            )

        return None


class SerialReaderThread(threading.Thread):
    def __init__(self, serial: Serial, packet_queue: Queue) -> None:
        super().__init__(daemon=True, name="esp32c6-serial-reader")
        self.serial = serial
        self.packet_queue = packet_queue
        self.parser = SerialFrameReader(serial)
        self._stop = threading.Event()

    def run(self) -> None:
        while not self._stop.is_set():
            packet = self.parser.read_packet(READ_SLICE_SEC)
            if packet is not None:
                try:
                    self.packet_queue.put_nowait(packet)
                except Full:
                    pass
            else:
                time.sleep(0.01)

    def stop(self) -> None:
        self._stop.set()


def is_capture_serial_port(device: str, vid: Optional[int]) -> bool:
    """Ignore onboard /dev/ttyS* ports; keep USB serial adapters only."""
    if vid is not None:
        return True
    return (
        device.startswith("/dev/ttyACM")
        or device.startswith("/dev/ttyUSB")
        or device.startswith("/dev/cu.usb")
        or device.startswith("/dev/cu.wchusbserial")
        or device.startswith("/dev/cu.SLAB_USBtoUART")
        or device.upper().startswith("COM")
    )


class Esp32C6SnifferExtcap:
    def __init__(self) -> None:
        self.first_host_us: Optional[int] = None
        self.first_device_us: Optional[int] = None

    @staticmethod
    def extcap_interfaces() -> str:
        lines = [
            "extcap {version=1.2.0}"
            "{help=https://github.com/Esp32ZigSniff}"
            "{display=ESP32-C6 802.15.4 Sniffer}",
            f"control {{number={CTRL_LOGGER}}}{{type=button}}{{role=logger}}"
            "{display=Log}{tooltip=Show capture log}",
        ]
        for port in comports():
            if not is_capture_serial_port(port.device, port.vid):
                continue
            label = port.description or "USB serial"
            if port.vid == ESPRESSIF_USB_VID:
                label = f"Espressif USB JTAG/serial ({label})"
            lines.append(
                f"interface {{value={port.device}}}{{display={port.device} - {label}}}"
            )
        return "\n".join(lines)

    @staticmethod
    def extcap_dlts() -> str:
        return "\n".join(
            [
                f"dlt {{number={DLT.IEEE802_15_4_TAP}}}"
                "{name=IEEE802_15_4_TAP}{display=IEEE 802.15.4 TAP}",
                f"dlt {{number={DLT.IEEE802_15_4_NOFCS}}}"
                "{name=IEEE802_15_4_NOFCS}{display=IEEE 802.15.4 without FCS}",
            ]
        )

    @staticmethod
    def extcap_config() -> str:
        lines = [
            "arg {number=0}{call=--channel}{display=Channel}"
            "{tooltip=IEEE 802.15.4 channel (11-26)}{type=selector}{required=true}{default=15}",
            "arg {number=1}{call=--scan}{display=Scan mode}"
            "{tooltip=Scan all channels or stay on selected channel}{type=selector}{default=off}",
            "arg {number=2}{call=--baudrate}{display=Baud rate}"
            "{tooltip=Serial baud rate (ignored for USB Serial/JTAG)}{type=selector}{default=115200}",
        ]
        for ch in range(11, 27):
            default = "true" if ch == 15 else "false"
            lines.append(f"value {{arg=0}}{{value={ch}}}{{display={ch}}}{{default={default}}}")
        lines.append("value {arg=1}{value=off}{display=Fixed channel}{default=true}")
        lines.append("value {arg=1}{value=on}{display=Scan channels 11-26}{default=false}")
        for baud in (115200, 230400, 460800):
            default = "true" if baud == DEFAULT_BAUDRATE else "false"
            lines.append(
                f"value {{arg=2}}{{value={baud}}}{{display={baud}}}{{default={default}}}"
            )
        return "\n".join(lines)

    def correct_timestamp(self, device_us: int) -> int:
        if self.first_host_us is None:
            self.first_host_us = int(time.time() * 1_000_000)
            self.first_device_us = device_us
            return self.first_host_us
        assert self.first_device_us is not None
        return self.first_host_us - self.first_device_us + device_us

    @staticmethod
    def configure_device(serial: Serial, channel: int, scan: str) -> None:
        serial.reset_input_buffer()
        time.sleep(0.15)
        serial.write(b"wireshark on\n")
        time.sleep(0.1)
        if scan == "on":
            serial.write(b"scan on\n")
        else:
            serial.write(b"scan off\n")
            time.sleep(0.05)
            serial.write(f"ch {channel}\n".encode("ascii"))
        serial.flush()
        time.sleep(0.2)
        serial.reset_input_buffer()

    def capture(
        self,
        port: str,
        fifo_path: str,
        channel: int,
        scan: str,
        baudrate: int,
        use_tap: bool = True,
        control_in: Optional[str] = None,
    ) -> None:
        dlt = DLT.IEEE802_15_4_TAP if use_tap else DLT.IEEE802_15_4_NOFCS
        packet_queue: Queue = Queue(maxsize=512)
        drain_control_fifo(control_in)

        with Serial(port, baudrate=baudrate, timeout=0.25) as serial, open(
            fifo_path, "wb", buffering=0
        ) as fifo:
            fifo.write(pcap_global_header(dlt.value))
            reader_thread = SerialReaderThread(serial, packet_queue)
            reader_thread.start()
            self.configure_device(serial, channel, scan)

            while True:
                try:
                    packet = packet_queue.get(timeout=QUEUE_GET_TIMEOUT_SEC)
                except Empty:
                    continue

                if not is_valid_psdu(packet.psdu):
                    continue

                ts_us = self.correct_timestamp(packet.timestamp_us)
                if use_tap:
                    payload = build_tap_packet(
                        packet.channel, packet.rssi, packet.lqi, packet.psdu
                    )
                else:
                    payload = packet.psdu
                fifo.write(pcap_packet(ts_us, payload))


def main() -> int:
    parser = argparse.ArgumentParser(description="ESP32-C6 802.15.4 Wireshark extcap")
    parser.add_argument("--extcap-interfaces", action="store_true")
    parser.add_argument("--extcap-interface")
    parser.add_argument("--extcap-dlts", action="store_true")
    parser.add_argument("--extcap-config", action="store_true")
    parser.add_argument("--capture", action="store_true")
    parser.add_argument("--fifo")
    parser.add_argument("--extcap-control-in")
    parser.add_argument("--extcap-control-out")
    parser.add_argument("--extcap-version")
    parser.add_argument("--channel", type=int, default=15)
    parser.add_argument("--scan", choices=("on", "off"), default="off")
    parser.add_argument("--baudrate", type=int, default=DEFAULT_BAUDRATE)
    parser.add_argument("--no-tap", action="store_true")
    parser.add_argument("-o", "--output", help="Write PCAP to a file instead of Wireshark FIFO")
    args, unknown = parser.parse_known_args()

    if unknown:
        print(f"WARNING: ignoring unknown arguments: {unknown}", file=sys.stderr)

    extcap = Esp32C6SnifferExtcap()

    if args.extcap_interfaces:
        print(extcap.extcap_interfaces())
        return 0
    if args.extcap_config:
        print(extcap.extcap_config())
        return 0
    if args.extcap_dlts:
        print(extcap.extcap_dlts())
        return 0

    if args.capture or args.output:
        if not args.extcap_interface:
            print("ERROR: --extcap-interface is required", file=sys.stderr)
            return 1
        sink = args.output or args.fifo
        if not sink:
            print("ERROR: --capture requires --fifo or use -o/--output", file=sys.stderr)
            return 1
        try:
            extcap.capture(
                args.extcap_interface,
                sink,
                args.channel,
                args.scan,
                args.baudrate,
                use_tap=not args.no_tap,
                control_in=args.extcap_control_in,
            )
        except KeyboardInterrupt:
            return 0
        except Exception as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
