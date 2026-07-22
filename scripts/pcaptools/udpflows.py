"""Analysis of candidate proprietary UDP flows (payload-level).

For each UDP conversation this reports payload-length distribution, common
header bytes, byte entropy, and any sequence-counter-like fields -- the
fingerprints of a proprietary P2P/streaming protocol. It deliberately
prints only the first few payload bytes, never whole payloads, to avoid
dumping sensitive data.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from statistics import mean
from typing import Optional

from .analyze import shannon_entropy
from .model import Endpoint, PacketRow

# Ports we consider "known" and exclude from proprietary-flow analysis.
_KNOWN_UDP_PORTS = {53, 67, 68, 123, 5353, 1900, 3702, 137, 138, 5355}


@dataclass
class DirectionStats:
    packets: int = 0
    payload_bytes: int = 0
    lengths: Counter = field(default_factory=Counter)
    entropies: list[float] = field(default_factory=list)
    first_payloads: list[bytes] = field(default_factory=list)  # capped sample

    def add(self, payload: bytes, cap: int = 200) -> None:
        self.packets += 1
        self.payload_bytes += len(payload)
        self.lengths[len(payload)] += 1
        self.entropies.append(shannon_entropy(payload))
        if len(self.first_payloads) < cap:
            self.first_payloads.append(payload)

    @property
    def mean_entropy(self) -> float:
        return mean(self.entropies) if self.entropies else 0.0


@dataclass
class UdpFlow:
    a: Endpoint
    b: Endpoint
    ab: DirectionStats = field(default_factory=DirectionStats)  # a -> b
    ba: DirectionStats = field(default_factory=DirectionStats)  # b -> a

    @property
    def packets(self) -> int:
        return self.ab.packets + self.ba.packets


def _canonical(src: Endpoint, dst: Endpoint) -> tuple[Endpoint, Endpoint, bool]:
    def k(ep: Endpoint) -> tuple[str, int]:
        return (ep[0], ep[1] if ep[1] is not None else -1)

    if k(src) <= k(dst):
        return src, dst, True
    return dst, src, False


def collect_udp_flows(
    rows,
    *,
    include_known_ports: bool = False,
) -> dict[tuple, UdpFlow]:
    flows: dict[tuple, UdpFlow] = {}
    for r in rows:
        if r.l4 != "udp" or r.payload is None:
            continue
        if not include_known_ports and (
            (r.srcport in _KNOWN_UDP_PORTS) or (r.dstport in _KNOWN_UDP_PORTS)
        ):
            continue
        src_ep: Endpoint = (r.src or "", r.srcport)
        dst_ep: Endpoint = (r.dst or "", r.dstport)
        a, b, src_is_a = _canonical(src_ep, dst_ep)
        key = (a, b)
        flow = flows.get(key)
        if flow is None:
            flow = UdpFlow(a=a, b=b)
            flows[key] = flow
        (flow.ab if src_is_a else flow.ba).add(r.payload)
    return flows


def common_prefix(payloads: list[bytes], max_len: int = 16) -> bytes:
    if not payloads:
        return b""
    shortest = min(min(len(p) for p in payloads), max_len)
    prefix = bytearray()
    for i in range(shortest):
        b0 = payloads[0][i]
        if all(p[i] == b0 for p in payloads):
            prefix.append(b0)
        else:
            break
    return bytes(prefix)


def detect_sequence_field(
    payloads: list[bytes],
    *,
    max_offset: int = 12,
) -> Optional[dict]:
    """Look for a monotonically increasing integer field across payloads.

    Returns the best candidate as a dict, or None. Checks 2- and 4-byte
    fields, both endiannesses, at each offset. A field qualifies if it is
    increasing (allowing wraparound) in the large majority of consecutive
    packet pairs.
    """
    usable = [p for p in payloads if len(p) >= 4]
    if len(usable) < 5:
        return None

    best: Optional[dict] = None
    for width in (2, 4):
        modulo = 1 << (8 * width)
        for endian in ("big", "little"):
            for off in range(0, max_offset + 1):
                vals = []
                ok = True
                for p in usable:
                    if off + width > len(p):
                        ok = False
                        break
                    vals.append(int.from_bytes(p[off : off + width], endian))
                if not ok or len(vals) < 5:
                    continue
                incr = 0
                for x, y in zip(vals, vals[1:]):
                    delta = (y - x) % modulo
                    # small positive step (counter) but not "everything moved"
                    if 0 < delta <= max(16, modulo // 4):
                        incr += 1
                ratio = incr / (len(vals) - 1)
                if ratio >= 0.8 and (best is None or ratio > best["ratio"]):
                    best = {
                        "offset": off,
                        "width": width,
                        "endian": endian,
                        "ratio": round(ratio, 3),
                        "sample": vals[:8],
                    }
    return best


def analyze_flow(flow: UdpFlow) -> dict:
    def dir_report(d: DirectionStats) -> dict:
        payloads = d.first_payloads
        prefix = common_prefix(payloads)
        return {
            "packets": d.packets,
            "payload_bytes": d.payload_bytes,
            "length_distribution": dict(sorted(d.lengths.items())),
            "mean_entropy_bits_per_byte": round(d.mean_entropy, 2),
            "common_prefix_hex": prefix.hex(),
            "first_payload_head_hex": payloads[0][:16].hex() if payloads else "",
            "sequence_field": detect_sequence_field(payloads),
        }

    return {
        "endpoints": f"{_fmt(flow.a)} <-> {_fmt(flow.b)}",
        "total_packets": flow.packets,
        "a_to_b": dir_report(flow.ab),
        "b_to_a": dir_report(flow.ba),
    }


def _fmt(ep: Endpoint) -> str:
    ip, port = ep
    return f"{ip}:{port}" if port is not None else ip
