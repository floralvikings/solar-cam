#!/usr/bin/env python3
"""Extract every DNS query and answer from a capture.

Read-only. Requires tshark. Produces the list of hostnames the camera (and
phone) resolve -- the first step in mapping cloud dependencies.

Examples:
    python scripts/extract_dns.py captures/boot.pcap
    python scripts/extract_dns.py captures/boot.pcap --camera-ip 192.168.50.42
    python scripts/extract_dns.py captures/boot.pcap --json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter

from pcaptools.tshark import (
    TsharkError,
    TsharkNotFound,
    read_packets,
    tshark_version,
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="List DNS queries/answers from a capture (read-only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("pcap", help="Path to a .pcap/.pcapng file")
    p.add_argument(
        "--camera-ip",
        help="If set, only show queries sourced from this IP (the camera).",
    )
    p.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    p.add_argument("--tshark", help="Explicit path to the tshark binary.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        print(f"[i] using {tshark_version(args.tshark)}", file=sys.stderr)
        rows = read_packets(args.pcap, display_filter="dns", tshark_bin=args.tshark)

        queries: Counter[str] = Counter()
        answers: dict[str, set[str]] = {}
        for r in rows:
            if not r.dns_query:
                continue
            if args.camera_ip and r.src != args.camera_ip and not r.dns_answers:
                # Skip queries not from the camera (responses come from resolver).
                if r.src != args.camera_ip:
                    continue
            queries[r.dns_query] += 1
            if r.dns_answers:
                answers.setdefault(r.dns_query, set()).update(r.dns_answers)
    except TsharkNotFound as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except TsharkError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if args.json:
        out = {
            "queries": dict(queries),
            "answers": {k: sorted(v) for k, v in answers.items()},
        }
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        print(f"DNS names resolved ({len(queries)} unique):")
        for name, n in sorted(queries.items()):
            ans = answers.get(name)
            ans_s = f"  -> {', '.join(sorted(ans))}" if ans else ""
            print(f"  {name}  (x{n}){ans_s}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
