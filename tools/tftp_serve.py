"""Minimal read-only TFTP server, to push files onto the camera.

``rbxsend`` only moves data camera -> host. For the other direction the device
already has what we need: busybox ships ``tftp``. This serves a directory
read-only so the camera can pull binaries into ``/tmp`` and run them **without
flashing anything**, which turns firmware experiments into an ordinary
edit-run loop:

    # here
    .venv/bin/python tools/tftp_serve.py --dir /path/to/files --port 6969

    # on the camera
    tftp -g -r prudynt -l /tmp/prudynt <host> 6969
    chmod +x /tmp/prudynt

A high port is the default because binding 69 needs root on macOS, and busybox
``tftp`` takes the port as a trailing argument.

Read requests only: write requests are refused, so a camera cannot alter
anything on this side.
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
from pathlib import Path

OP_RRQ, OP_WRQ, OP_DATA, OP_ACK, OP_ERROR = 1, 2, 3, 4, 5
BLOCK = 512


def send_error(sock, addr, code: int, msg: str) -> None:
    sock.sendto(struct.pack("!HH", OP_ERROR, code) + msg.encode() + b"\x00", addr)


def serve_file(sock: socket.socket, addr, path: Path, blksize: int) -> None:
    data = path.read_bytes()
    total = (len(data) + blksize) // blksize
    print(f"   sending {path.name}: {len(data)} bytes in {total} blocks")
    block = 1
    offset = 0
    while True:
        chunk = data[offset:offset + blksize]
        pkt = struct.pack("!HH", OP_DATA, block & 0xFFFF) + chunk
        for attempt in range(5):
            sock.sendto(pkt, addr)
            try:
                resp, raddr = sock.recvfrom(1024)
            except socket.timeout:
                continue
            if raddr != addr or len(resp) < 4:
                continue
            op, ack = struct.unpack("!HH", resp[:4])
            if op == OP_ERROR:
                print(f"   client error: {resp[4:].decode('utf-8','replace')}")
                return
            if op == OP_ACK and ack == (block & 0xFFFF):
                break
        else:
            print(f"   timeout on block {block}; aborting")
            return
        offset += blksize
        if len(chunk) < blksize:
            print(f"   done ({block} blocks)")
            return
        block += 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", required=True, help="directory to serve (read-only)")
    ap.add_argument("--port", type=int, default=6969)
    ap.add_argument("--timeout", type=float, default=300.0,
                    help="exit after this long with no request (default 300s)")
    args = ap.parse_args()

    root = Path(args.dir).resolve()
    if not root.is_dir():
        raise SystemExit(f"{root} is not a directory")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", args.port))
    sock.settimeout(args.timeout)
    print(f"TFTP (read-only) on 0.0.0.0:{args.port} serving {root}")
    for f in sorted(root.iterdir()):
        if f.is_file():
            print(f"   {f.name}  ({f.stat().st_size} bytes)")

    while True:
        try:
            req, addr = sock.recvfrom(2048)
        except socket.timeout:
            print("idle timeout; exiting")
            return 0
        if len(req) < 4:
            continue
        op = struct.unpack("!H", req[:2])[0]
        if op == OP_WRQ:
            send_error(sock, addr, 2, "read-only server")
            print(f"   refused write request from {addr[0]}")
            continue
        if op != OP_RRQ:
            continue
        fields = req[2:].split(b"\x00")
        name = fields[0].decode("utf-8", "replace")
        opts = {fields[i].decode().lower(): fields[i + 1].decode()
                for i in range(2, len(fields) - 1, 2) if fields[i]}
        print(f"\n<- RRQ {name!r} from {addr[0]} opts={opts or '{}'}")

        target = (root / Path(name).name).resolve()
        if target.parent != root or not target.is_file():
            send_error(sock, addr, 1, "file not found")
            print("   -> not found")
            continue

        blksize = BLOCK
        if "blksize" in opts:
            blksize = max(8, min(int(opts["blksize"]), 8192))
            oack = struct.pack("!H", 6) + b"blksize\x00" + str(blksize).encode() + b"\x00"
            sock.settimeout(5.0)
            sock.sendto(oack, addr)
            try:
                sock.recvfrom(1024)          # ACK 0
            except socket.timeout:
                blksize = BLOCK
        sock.settimeout(5.0)
        serve_file(sock, addr, target, blksize)
        sock.settimeout(args.timeout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
