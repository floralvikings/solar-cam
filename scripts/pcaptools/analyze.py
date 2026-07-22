"""Pure analysis functions operating on :class:`PacketRow` iterables.

No tshark, no I/O -- these are the functions the unit tests drive with
hand-built packet lists.
"""

from __future__ import annotations

import ipaddress
import math
from collections import Counter
from collections.abc import Iterable
from statistics import mean, pstdev
from typing import Optional

from .model import Conversation, Endpoint, PacketRow, Summary

# Packet-size histogram buckets (upper bound inclusive, label).
_SIZE_BUCKETS: tuple[tuple[int, str], ...] = (
    (63, "0-63"),
    (127, "64-127"),
    (255, "128-255"),
    (511, "256-511"),
    (1023, "512-1023"),
    (1471, "1024-1471"),
    (65535, "1472+"),
)


def is_private_ip(ip: Optional[str]) -> bool:
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def is_multicast_ip(ip: Optional[str]) -> bool:
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_multicast
    except ValueError:
        return False


def size_bucket(length: int) -> str:
    for upper, label in _SIZE_BUCKETS:
        if length <= upper:
            return label
    return "1472+"


def _canonical(src: Endpoint, dst: Endpoint) -> tuple[Endpoint, Endpoint, bool]:
    """Return (a, b, src_is_a) with a <= b for a stable conversation key."""
    # Normalise None ports to -1 only for comparison purposes.
    def cmp_key(ep: Endpoint) -> tuple[str, int]:
        return (ep[0], ep[1] if ep[1] is not None else -1)

    if cmp_key(src) <= cmp_key(dst):
        return src, dst, True
    return dst, src, False


def guess_camera_ip(rows: Iterable[PacketRow]) -> Optional[str]:
    """Heuristic: the private IPv4 that appears in the most packets.

    Works when a capture is dominated by one local device (the camera).
    Callers should prefer an explicit --camera-ip.
    """
    counts: Counter[str] = Counter()
    for r in rows:
        for ip in (r.src, r.dst):
            if is_private_ip(ip) and not is_multicast_ip(ip):
                counts[ip] += 1  # type: ignore[index]
    if not counts:
        return None
    return counts.most_common(1)[0][0]


def summarize(
    rows: Iterable[PacketRow],
    path: str = "",
    camera_ip: Optional[str] = None,
) -> Summary:
    """Fold a stream of packets into a :class:`Summary`."""
    s = Summary(path=path, camera_ip=camera_ip)

    for r in rows:
        s.packet_count += 1
        s.total_bytes += r.length
        s.first_time = min(s.first_time, r.time)
        s.last_time = max(s.last_time, r.time)
        if r.protocol:
            s.protocol_counts[r.protocol] += 1
        if r.l4:
            s.l4_counts[r.l4] += 1
        if r.src:
            s.talkers[r.src] += 1
        if r.dst:
            s.talkers[r.dst] += 1
        s.size_histogram[size_bucket(r.length)] += 1

        # Server-port heuristic: the smaller port of the pair is more
        # likely the listening/service port. Only record for known l4.
        if r.l4 in ("tcp", "udp") and r.srcport is not None and r.dstport is not None:
            server_port = min(r.srcport, r.dstport)
            (s.tcp_ports if r.l4 == "tcp" else s.udp_ports)[server_port] += 1

        if r.dns_query:
            s.dns_queries[r.dns_query] += 1
            if r.dns_answers:
                s.dns_answers.setdefault(r.dns_query, set()).update(r.dns_answers)
        if r.sni:
            s.sni_names[r.sni] += 1

        _accumulate_conversation(s, r)

    if s.packet_count == 0:
        s.first_time = 0.0
        s.last_time = 0.0
    return s


def _accumulate_conversation(s: Summary, r: PacketRow) -> None:
    if not r.src or not r.dst or not r.l4:
        return
    src_ep: Endpoint = (r.src, r.srcport)
    dst_ep: Endpoint = (r.dst, r.dstport)
    a, b, src_is_a = _canonical(src_ep, dst_ep)
    key = (a, b, r.l4)
    conv = s.conversations.get(key)
    if conv is None:
        conv = Conversation(a=a, b=b, l4=r.l4)
        s.conversations[key] = conv
    if src_is_a:
        conv.packets_ab += 1
        conv.bytes_ab += r.length
    else:
        conv.packets_ba += 1
        conv.bytes_ba += r.length
    conv.first_time = min(conv.first_time, r.time)
    conv.last_time = max(conv.last_time, r.time)
    conv.times.append(r.time)
    conv.sizes.append(r.length)
    if r.protocol:
        conv.protocols[r.protocol] += 1


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte (0.0 = constant, 8.0 = uniform random)."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _inter_arrival_stats(times: list[float]) -> tuple[float, float]:
    """Return (mean_gap, coefficient_of_variation) for sorted timestamps."""
    if len(times) < 3:
        return (0.0, math.inf)
    ordered = sorted(times)
    gaps = [b - a for a, b in zip(ordered, ordered[1:]) if b - a >= 0]
    if not gaps:
        return (0.0, math.inf)
    m = mean(gaps)
    if m <= 0:
        return (0.0, math.inf)
    cv = pstdev(gaps) / m
    return (m, cv)


def suspected_keepalives(
    convs: Iterable[Conversation],
    *,
    max_mean_size: float = 200.0,
    min_packets: int = 6,
    max_cv: float = 0.6,
) -> list[Conversation]:
    """Flows of many small, regularly-spaced packets -- classic keepalives.

    Heuristic (all must hold):
      * mean packet size below ``max_mean_size`` bytes,
      * at least ``min_packets`` packets,
      * low inter-arrival coefficient of variation (regular cadence).
    """
    out = []
    for c in convs:
        if c.packets < min_packets:
            continue
        if c.mean_size > max_mean_size:
            continue
        _, cv = _inter_arrival_stats(c.times)
        if cv <= max_cv:
            out.append(c)
    out.sort(key=lambda c: c.packets, reverse=True)
    return out


def high_bandwidth_flows(
    convs: Iterable[Conversation],
    *,
    min_bytes: int = 100_000,
    min_bps: float = 20_000.0,
) -> list[Conversation]:
    """Flows likely to carry video/audio: high total bytes or byte-rate."""
    out = [
        c
        for c in convs
        if c.bytes_total >= min_bytes or c.bytes_per_second >= min_bps
    ]
    out.sort(key=lambda c: c.bytes_total, reverse=True)
    return out
