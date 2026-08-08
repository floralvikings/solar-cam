"""SAFE probe: ask the camera to fetch firmware from us, but never serve any.

Sends IOTYPE_USER_IPCAM_FIRMWARE_UPDATE_REQ (4631) over a **relay-path (0x1105)
session**, pointing the camera at an HTTP URL on this host. The listener logs
every byte of the request and answers ``404 Not Found`` with no body, so the
download always fails and the camera can never reach its MD5/CRC check, let
alone ``flashcp``. Nothing is written to the camera.

Why it matters: the OTA path in ``ubia_t23`` is
``download -> /tmp/update.bin -> image head CRC + MD5 -> /sbin/flashcp /dev/mtd3
(and /dev/mtd4)``. It never touches mtd0 (U-Boot) or mtd2 (kernel), so a bad
image cannot brick the bootloader, and there is **no signature check**. If the
camera fetches from a URL we choose, custom firmware becomes reachable over the
network with no hardware work at all.

Struct verified two ways (they agree):
  * app  — ``AVIOCTRLDEFs.SMsgAVIOCtrlFirmwareUpdateReq.getData()``, sent via
    ``AdvancedSettings.updateFw()`` as ``sendIoCtrl(data, 4631)``
  * device — ``src/ubia_update.c`` strings in ``ubia_t23``

``file_type`` decides which downloader runs, and they end in different places
(see docs/firmware-analysis.md for the full table). Verified live:

    0  -> answers 4632, spawns nothing, and LATCHES g_update_flag so every
          later 4631 is ignored until the camera reboots. Never send this.
    1  -> single fetch -> ubia_ota_update_liteos -> flashcp /dev/mtd4  <-- the
          only path that flashes the main SoC
    2  -> five fetches -> download_auto_update(type=2) -> "unknow type", no write
    10 -> five fetches -> /tmp/update_hi3861.bin (the ESP32 Wi-Fi part)
    11 -> rejected before the thread; would have been mtd3. Also latches the flag.

The five-versus-one connection count is ``download_auto_update``'s
``reDownloadCount < 5`` retry loop, and is how the two downloaders are told apart
on the wire.

Usage:  .venv/bin/python tools/fwtest.py [--port 8080] [--ftype 1] [--all]
"""

from __future__ import annotations

import argparse
import hashlib
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, "tools")

import p4p_probe_config as cfg  # noqa: E402  (puts the repo root on sys.path)
from p4p_relay import open_relay_session  # noqa: E402

FW_UPDATE_CHECK_REQ = 4629    # IOTYPE_USER_IPCAM_FIRMWARE_UPDATE_CHECK_REQ
FW_UPDATE_CHECK_RSP = 4630
FW_UPDATE_REQ = 4631          # IOTYPE_USER_IPCAM_FIRMWARE_UPDATE_REQ
FW_UPDATE_RSP = 4632
PATH = "/fw-probe.bin"

_404 = (b"HTTP/1.1 404 Not Found\r\nServer: fwtest\r\n"
        b"Content-Length: 0\r\nConnection: close\r\n\r\n")


class Listener:
    """Raw TCP logger that always answers 404.

    Deliberately not :mod:`http.server`: the camera's downloader is a hand-rolled
    socket client (``ubia_http_download`` / ``get_resp_header``), so a request it
    formats unusually must still be recorded. A bare TCP connect with no request
    at all is already proof the command was accepted.
    """

    def __init__(self, port: int) -> None:
        self.hits: list[tuple[str, str, bytes]] = []
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("0.0.0.0", port))
        self._sock.listen(8)
        self._sock.settimeout(0.5)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()

    def _handle(self, conn: socket.socket, addr: tuple[str, int]) -> None:
        conn.settimeout(3.0)
        data = b""
        try:
            while b"\r\n\r\n" not in data and len(data) < 8192:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
        except OSError:
            pass
        self.hits.append((time.strftime("%H:%M:%S"), addr[0], data))
        print(f"\n   !!! TCP connect from {addr[0]}:{addr[1]} "
              f"({len(data)} request bytes) -> answering 404")
        if data:
            for line in data.split(b"\r\n"):
                if line:
                    print(f"       | {line.decode('utf-8', 'replace')}")
        try:
            conn.sendall(_404)
        except OSError:
            pass
        conn.close()

    def stop(self) -> None:
        self._stop.set()
        self._sock.close()


def fw_payload(url: str, *, size: int = 1024, version: int = 0x7FFFFFFF,
               ftype: int = 0) -> bytes:
    """SMsgAVIOCtrlFirmwareUpdateReq: 172 bytes.

    ``version`` u32 LE @0, ``file_type`` @4, ``file_url_len`` @5,
    ``file_md5_len`` @6, ``resv`` @7, ``file_size`` u32 LE @8,
    ``md5sum`` (32 ASCII hex) @12, ``file_url`` (128) @44.

    The MD5 is deliberately wrong — belt and braces on top of the 404, so even a
    firmware that ignored the HTTP status could not proceed to flash.
    """
    md5 = hashlib.md5(b"deliberately-wrong").hexdigest().encode()
    url_b = url.encode()
    if len(url_b) > 128:
        raise ValueError("file_url field is 128 bytes")
    d = bytearray(172)
    struct.pack_into("<I", d, 0, version)
    d[4] = ftype
    d[5] = len(url_b)
    d[6] = len(md5)
    d[7] = 0
    struct.pack_into("<I", d, 8, size)
    d[12:12 + len(md5)] = md5
    d[44:44 + len(url_b)] = url_b
    return bytes(d)


def check_payload(*, ftype: int = 0, version: int = 0x7FFFFFFF) -> bytes:
    """SMsgAVIoctrlFirmwareUpdateCheckReq: file_type(1) resv(3) version(u32 LE)."""
    return bytes([ftype, 0, 0, 0]) + struct.pack("<I", version)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8080, help="local HTTP port to offer (default 8080)")
    ap.add_argument("--all", action="store_true",
                    help="try every file_type variant even after a fetch is seen")
    ap.add_argument("--wait", type=float, default=12.0,
                    help="seconds to wait for a fetch after each command (default 12)")
    ap.add_argument("--ftype", type=int, action="append",
                    help="only try this file_type (repeatable). Default: 1 then 2")
    ap.add_argument("--version", type=lambda s: int(s, 0), default=None,
                    help="override the offered firmware version")
    ap.add_argument("--no-check", action="store_true",
                    help="skip the 4629 UPDATE_CHECK probe")
    args = ap.parse_args()

    listener = Listener(args.port)
    url = f"http://{cfg.CLIENT_IP}:{args.port}{PATH}"
    print(f"listener on 0.0.0.0:{args.port} — always 404, never serves an image")
    print(f"URL offered to the camera: {url}\n")

    try:
        session = open_relay_session()
    except RuntimeError as exc:
        listener.stop()
        print(f"error: {exc}", file=sys.stderr)
        return 1

    # Only 1 and 2 reach pthread_create; the app picks the value out of the
    # vendor cloud's JSON, and type 2 is the one it flags by forcing bit 24 of
    # the version. 0x7fffffff / 0x01ffffff are unconditionally newer than the
    # installed 2455.0.21.10, so the "version == current" early-out cannot fire.
    defaults = [(1, 0x7FFFFFFF), (2, 0x01FFFFFF)]
    if args.ftype:
        defaults = [(t, 0x01FFFFFF if t == 2 else 0x7FFFFFFF) for t in args.ftype]
    variants = [(t, args.version if args.version is not None else v,
                 f"ftype={t} ver=0x{(args.version if args.version is not None else v):x}")
                for t, v in defaults]

    if not args.no_check:
        print(f"\n-> {FW_UPDATE_CHECK_REQ} FIRMWARE_UPDATE_CHECK_REQ")
        session.send_ioctrl(FW_UPDATE_CHECK_REQ, check_payload())
        for r in session.pump(5.0):
            print(f"   <- ioType {r.iotype}: {r.data[:64].hex()}")

    for ftype, version, tag in variants:
        print(f"\n-> {FW_UPDATE_REQ} FIRMWARE_UPDATE_REQ  [{tag}]")
        session.send_ioctrl(FW_UPDATE_REQ, fw_payload(url, version=version, ftype=ftype))
        for r in session.pump(args.wait):
            print(f"   <- ioType {r.iotype}: {r.data[:64].hex()}")
        if listener.hits and not args.all:
            break

    print("\nsettling…")
    session.pump(15.0)
    session.close()
    listener.stop()

    print(f"\n{'=' * 70}")
    print(f"TCP connections received : {len(listener.hits)}")
    for when, ip, data in listener.hits:
        first = data.split(b"\r\n", 1)[0].decode("utf-8", "replace") if data else "(no data)"
        print(f"   {when}  {ip}  {first}")
    interesting = [r for r in session.responses
                   if r.iotype in (FW_UPDATE_CHECK_RSP, FW_UPDATE_RSP)]
    print(f"ioctrl responses         : {len(session.responses)}"
          f" ({len(interesting)} update-related)")
    for r in session.responses[:12]:
        print(f"   ioType {r.iotype:<6} {len(r.data):>4}B  {r.data[:48].hex()}")

    if listener.hits:
        print("\n>>> CAMERA FETCHED — network flashing is viable.")
    elif interesting:
        print("\n>>> command ACCEPTED and answered, but no fetch — "
              "read the response codes above before concluding.")
    else:
        print("\n>>> no 4632 at all: g_update_flag is probably still set from an "
              "earlier request (file_type=0 latches it). Reboot the camera and retry.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
