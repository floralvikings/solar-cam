"""Receive one raw byte stream on a TCP port and write it to a file.

Companion to ``rbxsend`` on the camera, for payloads too big for
``recon_run.py`` (whose listener deliberately caps at 1 MB). The intended use is
pulling the **whole flash** off the running device::

    # here
    .venv/bin/python tools/recv_blob.py --out captures/primary_mtd11.bin

    # on the camera, over telnet
    dd if=/dev/mtd11 bs=64k | /system/bin/rbxsend

``/dev/mtd11`` is the vendor's own ``"all"`` partition — the entire 8 MB device.
Reading it this way replaces the chip-off procedure that was previously the only
route to the *primary* camera's unique per-device data (UID, MAC, Wi-Fi
credentials, AE calibration), none of which exist in the spare's dump.

Writes exactly what arrives, reports size and SHA-256, and warns if the length
is not the expected 8 MiB so a truncated transfer cannot be mistaken for a
complete backup.
"""

from __future__ import annotations

import argparse
import hashlib
import socket
import sys
import time
from pathlib import Path

EXPECTED = 8 * 1024 * 1024


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--wait", type=float, default=600.0,
                    help="seconds to wait for the connection (default 600)")
    ap.add_argument("--expect", type=int, default=EXPECTED,
                    help="expected byte count; 0 disables the check")
    args = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", args.port))
    srv.listen(1)
    srv.settimeout(args.wait)
    print(f"listening on 0.0.0.0:{args.port} for one stream -> {args.out}")

    try:
        conn, addr = srv.accept()
    except socket.timeout:
        print("no connection within the timeout", file=sys.stderr)
        return 1
    print(f"connection from {addr[0]}:{addr[1]}, receiving…")

    conn.settimeout(120.0)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    started = time.time()
    digest = hashlib.sha256()
    with out.open("wb") as fh:
        while True:
            try:
                chunk = conn.recv(1 << 16)
            except socket.timeout:
                print("\nstalled for 120s; treating as end of stream")
                break
            if not chunk:
                break
            fh.write(chunk)
            digest.update(chunk)
            total += len(chunk)
            if total % (512 * 1024) < (1 << 16):
                elapsed = max(time.time() - started, 1e-3)
                print(f"   {total:>9} bytes  ({total / elapsed / 1024:.0f} KiB/s)")
    conn.close()
    srv.close()

    print(f"\nwrote {out}: {total} bytes")
    print(f"sha256: {digest.hexdigest()}")
    if args.expect and total != args.expect:
        print(f"\nWARNING: expected {args.expect} bytes — this transfer is "
              f"{'short' if total < args.expect else 'long'} and must NOT be "
              f"treated as a complete backup.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
