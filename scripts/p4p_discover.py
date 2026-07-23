#!/usr/bin/env python3
"""Discover an RBX-S73 camera on the LAN via the p4p protocol library.

Sends the UBIA/TUTK LAN-search (UDP 32762) and prints the parsed reply. This is
the first working leg of the local, cloud-free client (see docs/session-flow.md).

The camera returns an account name and a credential in its reply; the credential
is REDACTED by default. Pass --show-secrets only in a private terminal.

Examples:
    python scripts/p4p_discover.py --uid LXKH...            # broadcast search
    python scripts/p4p_discover.py --uid LXKH... --target 192.168.88.113
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from p4p.lansearch import discover  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Discover an RBX-S73 camera locally (p4p LAN search).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--uid", required=True, help="Device UID (20 chars). Secret.")
    p.add_argument(
        "--target",
        action="append",
        help="Address(es) to send to (default: 255.255.255.255 broadcast). "
        "May be repeated; add the camera IP for a unicast retry.",
    )
    p.add_argument("--timeout", type=float, default=8.0, help="Total seconds (radio warmup).")
    p.add_argument("--show-secrets", action="store_true", help="Print the credential in the clear.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    targets = args.target or ["255.255.255.255"]
    print(f"[i] LAN-searching for {args.uid} via {targets} (up to {args.timeout:.0f}s)...",
          file=sys.stderr)
    results = discover(args.uid, targets=targets, timeout=args.timeout)
    if not results:
        print("no camera responded (is it awake? try adding --target <camera-ip> "
              "and a longer --timeout for radio warmup)")
        return 1
    for info in results:
        shown = info if args.show_secrets else info.masked()
        print(f"\nCAMERA @ {info.source_ip}:{info.source_port}")
        print(f"  uid       : {shown.uid}")
        print(f"  account   : {shown.account}")
        print(f"  credential: {shown.credential}")
        print(f"  fields    : {shown.strings}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
