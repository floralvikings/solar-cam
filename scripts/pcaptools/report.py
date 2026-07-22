"""Human-readable text/JSON rendering for the CLI tools.

Kept separate from analysis so the analysis stays presentation-free.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

from .analyze import high_bandwidth_flows, suspected_keepalives
from .compare import Comparison, format_signature
from .model import Conversation, Summary


def _fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f}{unit}" if unit != "B" else f"{int(n)}B"
        n /= 1024
    return f"{n:.1f}GB"


def _fmt_time(epoch: float) -> str:
    if epoch <= 0:
        return "n/a"
    return _dt.datetime.fromtimestamp(epoch, _dt.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


def _conv_line(c: Conversation) -> str:
    return (
        f"  {c.endpoints_str():<48} {c.l4:<4} "
        f"pkts={c.packets:<6} bytes={_fmt_bytes(c.bytes_total):<9} "
        f"rate={_fmt_bytes(c.bytes_per_second)}/s "
        f"[{','.join(p for p, _ in c.protocols.most_common(3))}]"
    )


def render_summary_text(s: Summary, top: int = 15) -> str:
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append(f"PCAP SUMMARY: {s.path}")
    lines.append("=" * 72)
    lines.append(f"Packets      : {s.packet_count}")
    lines.append(f"Total bytes  : {_fmt_bytes(s.total_bytes)}")
    lines.append(
        f"Duration     : {s.duration:.1f}s "
        f"({_fmt_time(s.first_time)} -> {_fmt_time(s.last_time)})"
    )
    lines.append(f"Camera IP    : {s.camera_ip or '(not set; use --camera-ip)'}")

    lines.append("\n-- Protocols (tshark column) --")
    for proto, n in s.protocol_counts.most_common(top):
        lines.append(f"  {proto:<20} {n}")

    lines.append("\n-- Top talkers (by packets) --")
    for ip, n in s.talkers.most_common(top):
        lines.append(f"  {ip:<40} {n}")

    lines.append("\n-- TCP service ports --")
    if s.tcp_ports:
        for port, n in s.tcp_ports.most_common(top):
            lines.append(f"  {port:<8} {n}")
    else:
        lines.append("  (none)")

    lines.append("\n-- UDP service ports --")
    if s.udp_ports:
        for port, n in s.udp_ports.most_common(top):
            lines.append(f"  {port:<8} {n}")
    else:
        lines.append("  (none)")

    lines.append("\n-- DNS queries --")
    if s.dns_queries:
        for name, n in s.dns_queries.most_common(top):
            answers = s.dns_answers.get(name)
            ans = f" -> {', '.join(sorted(answers))}" if answers else ""
            lines.append(f"  {name}{ans}  (x{n})")
    else:
        lines.append("  (none)")

    lines.append("\n-- TLS SNI --")
    if s.sni_names:
        for name, n in s.sni_names.most_common(top):
            lines.append(f"  {name}  (x{n})")
    else:
        lines.append("  (none)")

    lines.append("\n-- Packet size distribution --")
    for _, label in (
        (63, "0-63"),
        (127, "64-127"),
        (255, "128-255"),
        (511, "256-511"),
        (1023, "512-1023"),
        (1471, "1024-1471"),
        (65535, "1472+"),
    ):
        n = s.size_histogram.get(label, 0)
        bar = "#" * min(40, n * 40 // max(1, s.packet_count))
        lines.append(f"  {label:<10} {n:<8} {bar}")

    convs = list(s.conversations.values())

    lines.append("\n-- Top conversations (by bytes) --")
    for c in sorted(convs, key=lambda c: c.bytes_total, reverse=True)[:top]:
        lines.append(_conv_line(c))

    hb = high_bandwidth_flows(convs)
    lines.append("\n-- High-bandwidth flows (likely video/audio) --")
    if hb:
        for c in hb[:top]:
            lines.append(_conv_line(c))
    else:
        lines.append("  (none above threshold)")

    ka = suspected_keepalives(convs)
    lines.append("\n-- Suspected keepalive flows (small, regular) --")
    if ka:
        for c in ka[:top]:
            lines.append(_conv_line(c))
    else:
        lines.append("  (none detected)")

    lines.append("")
    return "\n".join(lines)


def summary_to_dict(s: Summary) -> dict[str, Any]:
    convs = list(s.conversations.values())

    def conv_dict(c: Conversation) -> dict[str, Any]:
        return {
            "endpoints": c.endpoints_str(),
            "l4": c.l4,
            "packets": c.packets,
            "packets_ab": c.packets_ab,
            "packets_ba": c.packets_ba,
            "bytes": c.bytes_total,
            "bytes_ab": c.bytes_ab,
            "bytes_ba": c.bytes_ba,
            "duration_s": round(c.duration, 3),
            "bytes_per_second": round(c.bytes_per_second, 1),
            "protocols": dict(c.protocols),
        }

    return {
        "path": s.path,
        "packet_count": s.packet_count,
        "total_bytes": s.total_bytes,
        "duration_s": round(s.duration, 3),
        "first_time": s.first_time,
        "last_time": s.last_time,
        "camera_ip": s.camera_ip,
        "protocol_counts": dict(s.protocol_counts),
        "l4_counts": dict(s.l4_counts),
        "talkers": dict(s.talkers),
        "tcp_ports": dict(s.tcp_ports),
        "udp_ports": dict(s.udp_ports),
        "dns_queries": dict(s.dns_queries),
        "dns_answers": {k: sorted(v) for k, v in s.dns_answers.items()},
        "sni_names": dict(s.sni_names),
        "size_histogram": dict(s.size_histogram),
        "conversations": [conv_dict(c) for c in convs],
        "high_bandwidth_flows": [conv_dict(c) for c in high_bandwidth_flows(convs)],
        "suspected_keepalives": [conv_dict(c) for c in suspected_keepalives(convs)],
    }


def render_comparison_text(cmp: Comparison) -> str:
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append(f"SESSION COMPARISON: {', '.join(cmp.labels)}")
    lines.append(f"Camera IP: {cmp.camera_ip or '(not set)'}")
    lines.append("=" * 72)

    common = cmp.common_signatures()
    lines.append(f"\n-- Flows common to ALL {len(cmp.labels)} sessions --")
    if common:
        for sig in sorted(common, key=format_signature):
            lines.append(f"  {format_signature(sig)}")
    else:
        lines.append("  (none)")

    unique = cmp.unique_signatures()
    for label in cmp.labels:
        sigs = unique.get(label, [])
        lines.append(f"\n-- Flows UNIQUE to '{label}' --")
        if sigs:
            for sig in sorted(sigs, key=format_signature):
                agg = cmp.signatures[sig][label]
                lines.append(
                    f"  {format_signature(sig):<48} "
                    f"pkts={agg.packets} bytes={_fmt_bytes(agg.bytes)}"
                )
        else:
            lines.append("  (none)")

    udns = cmp.unique_dns()
    lines.append("\n-- DNS names unique to each session --")
    any_unique = False
    for label in cmp.labels:
        names = udns.get(label, set())
        if names:
            any_unique = True
            lines.append(f"  [{label}]")
            for name in sorted(names):
                lines.append(f"    {name}")
    if not any_unique:
        lines.append("  (none)")

    lines.append("\n-- Presence matrix (flow x session) --")
    header = "  " + "flow".ljust(46) + "".join(l[:10].ljust(11) for l in cmp.labels)
    lines.append(header)
    for sig in sorted(cmp.signatures.keys(), key=format_signature):
        present = cmp.signatures[sig]
        row = "  " + format_signature(sig).ljust(46)
        for label in cmp.labels:
            row += ("  X".ljust(11)) if label in present else ("  .".ljust(11))
        lines.append(row)

    lines.append("")
    return "\n".join(lines)
