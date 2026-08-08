"""*** THIS WRITES THE CAMERA'S FLASH. *** Serve an OTA image over ioType 4631.

Drives the one path that reaches a main-SoC write (see docs/firmware-analysis.md):

    4631 file_type=1 -> ubia_http_download -> download -> ubia_ota_update_liteos
      -> CRC the 32-byte header -> strip it -> /tmp/update.bin
      -> flashcp -v /tmp/update.bin /dev/mtd4

mtd4 is the `system` SquashFS: `ubia_t23`, `bin/gpiotool`, and the kernel
modules — including `esp32_sdio.ko`, the Wi-Fi driver. **A bad image costs the
network, and with it any second OTA attempt; recovery is then chip-off plus
`flashrom -w captures/flash_stock_verified.bin`.** U-Boot (mtd0) and the kernel
(mtd2) are never touched, so the board still boots either way.

Guards, in order:
  * the image is re-verified with scripts/ota_image.py and refused if invalid —
    a bad CRC would be rejected by the camera anyway, harmlessly, but there is
    no reason to send one;
  * the payload must carry SquashFS magic and fit the 1728K partition;
  * ``--confirm`` is mandatory; without it this only prints the plan;
  * ``--dry-run`` serves 404 instead of the image, exercising every other step.

Usage::

    .venv/bin/python tools/fwflash.py captures/noop_mtd4.img --dry-run
    .venv/bin/python tools/fwflash.py captures/noop_mtd4.img --confirm
"""

from __future__ import annotations

import argparse
import hashlib
import os
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, "tools")
sys.path.insert(0, "scripts")

import p4p_probe_config as cfg  # noqa: E402
from ota_image import HEADER_LEN, parse, payload_of, verify  # noqa: E402
from p4p_relay import open_relay_session  # noqa: E402

FW_UPDATE_REQ = 4631
SYSTEM_REBOOT_REQ = 4633
MTD4_SIZE = 1728 * 1024
SQUASHFS_MAGIC = b"hsqs"


class ImageServer:
    """Serves one image body to any requested path, with Content-Length.

    The camera's downloader hunts for a literal ``Content-Length:`` header and
    fails outright without one (`not find Content-Length:` @0x80e362).
    """

    def __init__(self, port: int, body: bytes | None) -> None:
        self.body = body
        self.requests: list[tuple[str, str]] = []
        self.served = 0
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("0.0.0.0", port))
        self._sock.listen(8)
        self._sock.settimeout(0.5)
        self._stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

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
        conn.settimeout(20.0)
        req = b""
        try:
            while b"\r\n\r\n" not in req and len(req) < 8192:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                req += chunk
            line = req.split(b"\r\n", 1)[0].decode("utf-8", "replace")
            self.requests.append((time.strftime("%H:%M:%S"), line))
            if self.body is None:
                print(f"   [dry-run] {addr[0]} {line} -> 404")
                conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n"
                             b"Connection: close\r\n\r\n")
            else:
                print(f"   >>> {addr[0]} {line} -> 200, sending {len(self.body)} bytes")
                conn.sendall(b"HTTP/1.1 200 OK\r\n"
                             b"Content-Type: application/octet-stream\r\n"
                             + f"Content-Length: {len(self.body)}\r\n".encode()
                             + b"Connection: close\r\n\r\n" + self.body)
                self.served += 1
                print(f"   >>> body sent in full ({self.served} total)")
        except OSError as exc:
            print(f"   !!! transfer error to {addr[0]}: {exc}")
        finally:
            conn.close()

    def stop(self) -> None:
        self._stop.set()
        self._sock.close()


def fw_payload(url: str, size: int, version: int = 0x7FFFFFFF, ftype: int = 1) -> bytes:
    """SMsgAVIOCtrlFirmwareUpdateReq. md5sum is left zero: the handler copies
    only payload[0x2c..0xac] and payload[8], so the MD5 is never read."""
    url_b = url.encode()
    d = bytearray(172)
    struct.pack_into("<I", d, 0, version)
    d[4] = ftype
    d[5] = len(url_b)
    d[6] = 32
    struct.pack_into("<I", d, 8, size)
    d[44:44 + len(url_b)] = url_b
    return bytes(d)


def check_image(image: bytes) -> list[str]:
    problems = []
    result = verify(image)
    if not result.ok:
        problems.append(f"container invalid: {result.reason}")
    payload = payload_of(image)
    if payload[:4] != SQUASHFS_MAGIC:
        problems.append(f"payload is not SquashFS (magic {payload[:4]!r}, want {SQUASHFS_MAGIC!r})")
    if len(payload) > MTD4_SIZE:
        problems.append(f"payload {len(payload)} > mtd4 size {MTD4_SIZE}")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("image", help="OTA image built by scripts/ota_image.py")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--confirm", action="store_true", help="actually do it")
    ap.add_argument("--dry-run", action="store_true",
                    help="run everything but serve 404 instead of the image")
    ap.add_argument("--reboot-first", action="store_true",
                    help="send 4633 and wait for the camera, to clear a latched g_update_flag")
    ap.add_argument("--wait", type=float, default=180.0,
                    help="seconds to watch after the command (default 180)")
    args = ap.parse_args()

    with open(args.image, "rb") as fh:
        image = fh.read()
    problems = check_image(image)
    header = parse(image)
    payload = payload_of(image)

    print(f"image    : {args.image}")
    print(f"  total  : {len(image)} bytes ({HEADER_LEN} header + {len(payload)} payload)")
    print(f"  crc    : 0x{header.crc:08x}")
    print(f"  sha256 : {hashlib.sha256(payload).hexdigest()}")
    print(f"  target : /dev/mtd4  (system SquashFS, {MTD4_SIZE} bytes)")
    for p in problems:
        print(f"  PROBLEM: {p}")
    if problems:
        print("\nrefusing to serve a bad image.", file=sys.stderr)
        return 2
    if not args.confirm:
        print("\nno --confirm given; nothing sent. This is the plan only.")
        return 0

    mode = "DRY RUN (404)" if args.dry_run else "*** WRITING FLASH ***"
    print(f"\n{mode}\n")

    server = ImageServer(args.port, None if args.dry_run else image)
    url = f"http://{cfg.CLIENT_IP}:{args.port}/fw.bin"
    print(f"serving on 0.0.0.0:{args.port}, offering {url}\n")

    try:
        session = open_relay_session()
    except RuntimeError as exc:
        server.stop()
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.reboot_first:
        print(f"-> {SYSTEM_REBOOT_REQ} SYSTEM_REBOOT_REQ (clears g_update_flag)")
        session.send_ioctrl(SYSTEM_REBOOT_REQ, b"\x00\x00\x00\x00")
        session.pump(5.0)
        session.close()
        server.stop()
        print("   rebooting; re-run without --reboot-first once it is back "
              "(tools/query_relay.py 960 is a good liveness check).")
        return 0

    print(f"-> {FW_UPDATE_REQ} FIRMWARE_UPDATE_REQ  file_type=1  file_size={len(image)}")
    session.send_ioctrl(FW_UPDATE_REQ, fw_payload(url, len(image)))
    deadline = time.time() + args.wait
    while time.time() < deadline:
        for reply in session.pump(5.0):
            print(f"   <- ioType {reply.iotype}: {reply.data[:32].hex()}")
        if server.served and time.time() > deadline - args.wait + 60:
            break
    session.close()
    server.stop()

    print(f"\n{'=' * 70}")
    print(f"HTTP requests : {len(server.requests)}")
    for when, line in server.requests:
        print(f"   {when}  {line}")
    print(f"bodies served : {server.served}")
    if server.served:
        print("\n>>> image delivered in full. The camera CRCs it, strips the header,\n"
              "    writes /tmp/update.bin and runs flashcp to /dev/mtd4, then reboots.\n"
              "    Confirm it comes back: tools/query_relay.py 960")
    else:
        print("\n>>> no body served — if there were no requests at all, g_update_flag "
              "is latched; re-run with --reboot-first.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
