"""Core data structures shared by every analysis tool.

Everything here is deliberately dependency-free (stdlib only) so the
analysis code can be exercised in unit tests with hand-built
``PacketRow`` lists, without tshark or a real capture file.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

# An endpoint is an (ip, port) pair. Port is None for L3-only packets
# (e.g. ICMP, ARP) where there is no transport port.
Endpoint = tuple[str, Optional[int]]


@dataclass(frozen=True)
class PacketRow:
    """One packet, flattened to the handful of fields we care about.

    Produced by :mod:`pcaptools.tshark`, but any code can construct these
    directly (that is what the unit tests do).
    """

    number: int
    time: float  # epoch seconds (frame.time_epoch)
    length: int  # frame.len (bytes on the wire)
    src: Optional[str] = None
    dst: Optional[str] = None
    l4: Optional[str] = None  # "tcp", "udp", "icmp", "igmp", or None
    srcport: Optional[int] = None
    dstport: Optional[int] = None
    protocol: Optional[str] = None  # tshark "Protocol" column, e.g. STUN/RTP/DNS
    dns_query: Optional[str] = None
    dns_answers: tuple[str, ...] = ()
    sni: Optional[str] = None
    payload: Optional[bytes] = None  # transport payload, only if requested

    @property
    def src_endpoint(self) -> Endpoint:
        return (self.src or "", self.srcport)

    @property
    def dst_endpoint(self) -> Endpoint:
        return (self.dst or "", self.dstport)


@dataclass
class Conversation:
    """A bidirectional flow between two endpoints over one L4 protocol.

    Endpoints are stored in a canonical order (``a <= b``) so that the two
    directions of the same flow collapse into a single conversation.
    """

    a: Endpoint
    b: Endpoint
    l4: str
    packets_ab: int = 0  # a -> b
    packets_ba: int = 0  # b -> a
    bytes_ab: int = 0
    bytes_ba: int = 0
    first_time: float = float("inf")
    last_time: float = float("-inf")
    protocols: Counter = field(default_factory=Counter)
    # Inter-arrival timestamps (sorted insertion order) for keepalive detection.
    times: list[float] = field(default_factory=list)
    sizes: list[int] = field(default_factory=list)

    @property
    def key(self) -> tuple[Endpoint, Endpoint, str]:
        return (self.a, self.b, self.l4)

    @property
    def packets(self) -> int:
        return self.packets_ab + self.packets_ba

    @property
    def bytes_total(self) -> int:
        return self.bytes_ab + self.bytes_ba

    @property
    def duration(self) -> float:
        if self.last_time < self.first_time:
            return 0.0
        return self.last_time - self.first_time

    @property
    def mean_size(self) -> float:
        return self.bytes_total / self.packets if self.packets else 0.0

    @property
    def bytes_per_second(self) -> float:
        d = self.duration
        return self.bytes_total / d if d > 0 else 0.0

    def endpoints_str(self) -> str:
        def fmt(ep: Endpoint) -> str:
            ip, port = ep
            return f"{ip}:{port}" if port is not None else ip

        return f"{fmt(self.a)} <-> {fmt(self.b)}"


@dataclass
class Summary:
    """Everything the PCAP summary tool reports for a single capture."""

    path: str
    packet_count: int = 0
    total_bytes: int = 0
    first_time: float = float("inf")
    last_time: float = float("-inf")
    camera_ip: Optional[str] = None
    protocol_counts: Counter = field(default_factory=Counter)
    l4_counts: Counter = field(default_factory=Counter)
    talkers: Counter = field(default_factory=Counter)  # per-IP packet counts
    tcp_ports: Counter = field(default_factory=Counter)  # remote/server tcp ports
    udp_ports: Counter = field(default_factory=Counter)  # remote/server udp ports
    dns_queries: Counter = field(default_factory=Counter)
    dns_answers: dict[str, set[str]] = field(default_factory=dict)
    sni_names: Counter = field(default_factory=Counter)
    conversations: dict[tuple, Conversation] = field(default_factory=dict)
    size_histogram: Counter = field(default_factory=Counter)

    @property
    def duration(self) -> float:
        if self.last_time < self.first_time:
            return 0.0
        return self.last_time - self.first_time
