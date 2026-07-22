#!/usr/bin/env python3
"""Payload-level report for candidate proprietary UDP flows.

For each UDP conversation (excluding well-known ports like DNS/mDNS/SSDP/
NTP unless --all-ports), report payload length distribution, common header
bytes, byte entropy, and any sequence-counter-like fields. This is the
tool for fingerprinting a proprietary P2P/streaming protocol.

Only the first few payload bytes are ever printed -- never whole payloads.

Read-only. Requires tshark. Does NOT need root.

Examples:
    python scripts/udp_flow_report.py captures/live-view.pcap
    python scripts/udp_flow_report.py captures/live-view.pcap --min-packets 20 --json
"""

from __future__ import annotations

import argparse
import json
import sys

from pcaptools.udpflows import analyze_flow, collect_udp_flows
from pcaptools.tshark import (
    TsharkError,
    TsharkNotFound,
    read_packets,
    tshark_version,
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Fingerprint proprietary UDP flows (read-only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("pcap", help="Path to a .pcap/.pcapng file")
    p.add_argument(
        "--all-ports",
        action="store_true",
        help="Include well-known UDP ports (DNS/mDNS/SSDP/NTP/...).",
    )
    p.add_argument(
        "--min-packets",
        type=int,
        default=5,
        help="Ignore flows with fewer than this many packets (default 5).",
    )
    p.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    p.add_argument("--tshark", help="Explicit path to the tshark binary.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        print(f"[i] using {tshark_version(args.tshark)}", file=sys.stderr)
        rows = read_packets(
            args.pcap,
            display_filter="udp",
            include_payload=True,
            tshark_bin=args.tshark,
        )
        flows = collect_udp_flows(rows, include_known_ports=args.all_ports)
    except TsharkNotFound as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except TsharkError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    reports = [
        analyze_flow(f)
        for f in sorted(flows.values(), key=lambda f: f.packets, reverse=True)
        if f.packets >= args.min_packets
    ]

    if args.json:
        print(json.dumps(reports, indent=2, sort_keys=True))
        return 0

    if not reports:
        print("No candidate UDP flows met the threshold.")
        return 0

    for rep in reports:
        print("=" * 72)
        print(f"FLOW: {rep['endpoints']}   packets={rep['total_packets']}")
        for direction in ("a_to_b", "b_to_a"):
            d = rep[direction]
            if d["packets"] == 0:
                continue
            print(f"  [{direction}] packets={d['packets']} "
                  f"payload_bytes={d['payload_bytes']} "
                  f"entropy={d['mean_entropy_bits_per_byte']} bits/byte")
            print(f"      common header : {d['common_prefix_hex'] or '(none)'}")
            print(f"      first 16 bytes: {d['first_payload_head_hex']}")
            lens = d["length_distribution"]
            top_lens = sorted(lens.items(), key=lambda kv: kv[1], reverse=True)[:6]
            print(f"      top lengths   : "
                  + ", ".join(f"{ln}B x{cnt}" for ln, cnt in top_lens))
            seq = d["sequence_field"]
            if seq:
                print(f"      SEQUENCE FIELD: offset={seq['offset']} "
                      f"width={seq['width']} {seq['endian']}-endian "
                      f"(confidence {seq['ratio']}), sample={seq['sample']}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
