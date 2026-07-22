#!/usr/bin/env python3
"""Compare RBX-S73 captures taken under different scenarios.

Highlights the flows, DNS names, and SNI values that appear ONLY during a
particular action (e.g. live view, pan, tilt) versus idle, and which are
common to every session. This is how we isolate the signaling/video
channels from ever-present keepalive/cloud traffic.

Read-only. Requires tshark. Does NOT need root.

Label each capture as LABEL=PATH:

    python scripts/compare_sessions.py \\
        idle=captures/idle.pcap \\
        live=captures/live-view.pcap \\
        pan=captures/pan.pcap \\
        wanblock=captures/wan-blocked.pcap \\
        --camera-ip 192.168.50.42

If you omit LABEL=, the file's basename is used as the label.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from pcaptools.analyze import guess_camera_ip, summarize
from pcaptools.compare import Comparison, compare_summaries, format_signature
from pcaptools.report import render_comparison_text
from pcaptools.tshark import (
    TsharkError,
    TsharkNotFound,
    read_packets,
    tshark_version,
)


def _split_spec(spec: str) -> tuple[str, str]:
    if "=" in spec:
        label, path = spec.split("=", 1)
        return label, path
    base = os.path.basename(spec)
    label = os.path.splitext(base)[0]
    return label, spec


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Compare RBX-S73 captures across scenarios (read-only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "captures",
        nargs="+",
        metavar="LABEL=PATH",
        help="Two or more captures to compare.",
    )
    p.add_argument("--camera-ip", help="Camera IP (recommended for clean signatures).")
    p.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    p.add_argument("--tshark", help="Explicit path to the tshark binary.")
    return p


def _comparison_to_dict(cmp: Comparison) -> dict:
    unique = cmp.unique_signatures()
    return {
        "labels": cmp.labels,
        "camera_ip": cmp.camera_ip,
        "common": [format_signature(s) for s in cmp.common_signatures()],
        "unique": {
            lbl: [format_signature(s) for s in sigs] for lbl, sigs in unique.items()
        },
        "unique_dns": {lbl: sorted(names) for lbl, names in cmp.unique_dns().items()},
        "matrix": {
            format_signature(sig): sorted(per.keys())
            for sig, per in cmp.signatures.items()
        },
    }


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if len(args.captures) < 2:
        print("error: provide at least two captures to compare.", file=sys.stderr)
        return 2

    try:
        version = tshark_version(args.tshark)
        print(f"[i] using {version}", file=sys.stderr)
    except TsharkNotFound as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    named = {}
    all_rows = []
    for spec in args.captures:
        label, path = _split_spec(spec)
        if label in named:
            print(f"error: duplicate label '{label}'", file=sys.stderr)
            return 2
        try:
            rows = list(read_packets(path, tshark_bin=args.tshark))
        except TsharkError as e:
            print(f"error reading {path}: {e}", file=sys.stderr)
            return 1
        all_rows.extend(rows)
        named[label] = summarize(rows, path=path, camera_ip=args.camera_ip)
        print(f"[i] {label}: {named[label].packet_count} packets", file=sys.stderr)

    camera_ip = args.camera_ip or guess_camera_ip(all_rows)
    if not args.camera_ip and camera_ip:
        print(f"[i] guessed camera IP: {camera_ip}", file=sys.stderr)

    cmp = compare_summaries(named, camera_ip=camera_ip)

    if args.json:
        print(json.dumps(_comparison_to_dict(cmp), indent=2, sort_keys=True))
    else:
        print(render_comparison_text(cmp))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
