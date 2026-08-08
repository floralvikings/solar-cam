"""Listen for the recon payload, trigger it, and read back the proof.

Pairs with the image from tools/build_system_image.py. Two independent hooks
live in that image, each with a network-free proof of execution, because we do
not know whether this vendor busybox ships any network applet at all:

  bin/tag_env_info  fires on any setting change. Forces ``md_level`` to the
                    sentinel 7. Trigger with ioType 804 SETMOTIONDETECT
                    ({u32 channel, u32 sensitivity}), read back with 806.
                    md_level == 7 after asking for something else ⇒ it ran.

  bin/mkfs.vfat     fires only from ioType 896, which only we send. Reboots the
                    camera ~15 s later. A drop-and-return ⇒ it ran.

The listener is a raw TCP socket rather than http.server so that even a bare
connection — a wget that reaches us but sends nothing we can parse — is
recorded. Anything received is saved under captures/.

Usage::

    .venv/bin/python tools/recon_run.py                                  # 896
    .venv/bin/python tools/recon_run.py --iotype 804 --hex 0000000003000000 --query 806
    .venv/bin/python tools/recon_run.py --no-trigger                     # listen only
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, "tools")

from p4p_relay import open_relay_session  # noqa: E402

OUT_DIR = Path("captures")
NAMES = {
    804: "SETMOTIONDETECT_REQ", 805: "SETMOTIONDETECT_RESP",
    806: "GETMOTIONDETECT_REQ", 807: "GETMOTIONDETECT_RESP",
    896: "FORMATEXTSTORAGE_REQ", 897: "FORMATEXTSTORAGE_RESP",
}
_OK = (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")


class Listener:
    """Raw TCP listener: records every connection, parseable or not."""

    def __init__(self, port: int) -> None:
        self.hits: list[tuple[str, str, bytes]] = []
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
        conn.settimeout(8.0)
        data = b""
        try:
            while len(data) < 1 << 20:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
                if data.endswith(b"\r\n\r\n") and b"Content-Length" not in data:
                    break
        except OSError:
            pass
        self.hits.append((time.strftime("%H:%M:%S"), addr[0], data))
        print(f"\n   <<< CONNECTION from {addr[0]}:{addr[1]} — {len(data)} bytes")
        try:
            conn.sendall(_OK)
        except OSError:
            pass
        conn.close()

    def stop(self) -> None:
        self._stop.set()
        self._sock.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--iotype", type=int, default=896)
    ap.add_argument("--hex", default=None,
                    help="request payload as hex (default: 8 zero bytes)")
    ap.add_argument("--query", type=int, default=None,
                    help="ioType to send afterwards to read the proof back (e.g. 806)")
    ap.add_argument("--wait", type=float, default=90.0)
    ap.add_argument("--no-trigger", action="store_true")
    args = ap.parse_args()

    listener = Listener(args.port)
    print(f"listening on 0.0.0.0:{args.port} (raw TCP — logs bare connects too)\n")

    session = None
    if not args.no_trigger:
        try:
            session = open_relay_session()
        except RuntimeError as exc:
            listener.stop()
            print(f"error: {exc}", file=sys.stderr)
            return 1
        payload = bytes.fromhex(args.hex) if args.hex else b"\x00" * 8
        print(f"-> {args.iotype} {NAMES.get(args.iotype, '')} payload={payload.hex()}")
        session.send_ioctrl(args.iotype, payload)
        for reply in session.pump(6.0):
            print(f"   <- ioType {reply.iotype} {NAMES.get(reply.iotype, '')}: "
                  f"{reply.data[:32].hex()}")
        if args.query is not None:
            print(f"\n-> {args.query} {NAMES.get(args.query, '')}  (reading the proof back)")
            session.send_ioctrl(args.query, b"\x00" * 8)
            for reply in session.pump(6.0):
                print(f"   <- ioType {reply.iotype} {NAMES.get(reply.iotype, '')}: "
                      f"{reply.data[:32].hex()}")

    deadline = time.time() + args.wait
    while time.time() < deadline and not listener.hits:
        if session is not None:
            for reply in session.pump(5.0):
                print(f"   <- ioType {reply.iotype} {NAMES.get(reply.iotype, '')}: "
                      f"{reply.data[:32].hex()}")
        else:
            time.sleep(1.0)
    if session is not None:
        session.close()
    listener.stop()

    print(f"\n{'=' * 70}")
    if not listener.hits:
        print("no connection from the camera.\n"
              "Check the network-free proofs instead:\n"
              "  * ioType 804 then 806 -> md_level == 7 means bin/tag_env_info ran\n"
              "  * ioType 896 -> camera reboots ~15s later means bin/mkfs.vfat ran\n"
              "If a proof fires but nothing arrives here, the hook works and the\n"
              "device simply has no usable network applet.")
        return 1

    OUT_DIR.mkdir(exist_ok=True)
    for i, (when, ip, body) in enumerate(listener.hits):
        print(f"{when}  {ip}  {len(body)} bytes")
        if not body:
            print("   (bare connection, no data — a network applet exists but "
                  "could not send)\n")
            continue
        dest = OUT_DIR / f"recon-{i}.txt"
        dest.write_bytes(body)
        print(f"   saved to {dest}\n")
        print(body.decode("utf-8", "replace"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
