#!/usr/bin/env python3
"""Decode (deobfuscate) a UBIA/TUTK P4P packet payload.

The obfuscation is a fixed transform reversed from libUBICAPIs.so; see
docs/protocol-notes.md. Accepts a hex payload on the command line or stdin.

WARNING: decoded device packets can contain the device UID, the account
name, and a credential string in the clear. Do not paste decoded output into
commits, issues, or anywhere shared. Redact before sharing.

Examples:
    python scripts/ubia_decode.py --hex 34858d2d62bc...     # decode
    python scripts/ubia_decode.py --encode --hex 07181000...  # encode
    echo 34858d... | python scripts/ubia_decode.py
"""

from __future__ import annotations

import argparse
import sys

from pcaptools.ubia_crypto import decode, encode


def _hexdump(data: bytes) -> str:
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {i:04x}  {hexs:<47}  {text}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Decode/encode a UBIA/TUTK P4P packet (read-only crypto).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--hex", help="Hex payload (else read hex from stdin)")
    p.add_argument("--encode", action="store_true", help="Encode instead of decode")
    p.add_argument("--raw", action="store_true", help="Emit raw hex, no hexdump")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    raw = args.hex if args.hex else sys.stdin.read()
    raw = "".join(raw.split())
    try:
        data = bytes.fromhex(raw)
    except ValueError as e:
        print(f"error: not valid hex: {e}", file=sys.stderr)
        return 2

    out = encode(data) if args.encode else decode(data)

    if args.raw:
        print(out.hex())
    else:
        print(_hexdump(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
