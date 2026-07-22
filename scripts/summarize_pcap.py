#!/usr/bin/env python3
"""Summarize a single PCAP/PCAPNG capture from the RBX-S73 camera.

Read-only. Requires tshark on PATH (or --tshark). Does NOT need root.

Reports capture duration, camera IP, protocol counts, endpoints, TCP/UDP
ports, DNS queries+answers, TLS SNI names, per-flow byte counts, the
packet-size distribution, suspected keepalive flows, and high-bandwidth
flows likely to contain video.

Examples:
    python scripts/summarize_pcap.py captures/live-view.pcap
    python scripts/summarize_pcap.py captures/idle.pcap --camera-ip 192.168.50.42
    python scripts/summarize_pcap.py captures/live-view.pcap --json > live.json
"""

from __future__ import annotations

import argparse
import json
import sys

from pcaptools.analyze import guess_camera_ip, summarize
from pcaptools.report import render_summary_text, summary_to_dict
from pcaptools.tshark import (
    TsharkError,
    TsharkNotFound,
    read_packets,
    tshark_version,
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Summarize an RBX-S73 packet capture (read-only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("pcap", help="Path to a .pcap/.pcapng file")
    p.add_argument(
        "--camera-ip",
        help="Camera IP (recommended). If omitted, guessed from the busiest "
        "private IPv4 address.",
    )
    p.add_argument(
        "--filter",
        dest="display_filter",
        help="Optional tshark display filter (e.g. 'ip.addr==192.168.50.42').",
    )
    p.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    p.add_argument(
        "--top", type=int, default=15, help="Rows per section in text mode (default 15)."
    )
    p.add_argument("--tshark", help="Explicit path to the tshark binary.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        version = tshark_version(args.tshark)
        print(f"[i] using {version}", file=sys.stderr)
        rows = list(
            read_packets(
                args.pcap,
                display_filter=args.display_filter,
                tshark_bin=args.tshark,
            )
        )
    except TsharkNotFound as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except TsharkError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    camera_ip = args.camera_ip or guess_camera_ip(rows)
    if not args.camera_ip and camera_ip:
        print(f"[i] guessed camera IP: {camera_ip}", file=sys.stderr)

    summary = summarize(rows, path=args.pcap, camera_ip=camera_ip)

    if args.json:
        print(json.dumps(summary_to_dict(summary), indent=2, sort_keys=True))
    else:
        print(render_summary_text(summary, top=args.top))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
