"""Compare captures taken under different scenarios (idle, live view,
pan, tilt, WAN-blocked, ...) to isolate what each action introduces.

The unit of comparison is a *flow signature*: the remote endpoint and
protocol, with the camera's own ephemeral port dropped so the same
logical flow matches across captures.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

from .analyze import is_private_ip
from .model import Conversation, Endpoint, Summary

# (remote_ip, remote_port, l4, dominant_protocol)
Signature = tuple[str, Optional[int], str, Optional[str]]


def _remote_endpoint(conv: Conversation, camera_ip: Optional[str]) -> Endpoint:
    a_ip = conv.a[0]
    b_ip = conv.b[0]
    if camera_ip:
        if a_ip == camera_ip:
            return conv.b
        if b_ip == camera_ip:
            return conv.a
    # Fallback: treat the public side as "remote".
    a_pub = not is_private_ip(a_ip)
    b_pub = not is_private_ip(b_ip)
    if a_pub != b_pub:
        return conv.a if a_pub else conv.b
    return conv.b


def flow_signature(conv: Conversation, camera_ip: Optional[str]) -> Signature:
    remote_ip, remote_port = _remote_endpoint(conv, camera_ip)
    dominant = conv.protocols.most_common(1)[0][0] if conv.protocols else None
    return (remote_ip, remote_port, conv.l4, dominant)


def format_signature(sig: Signature) -> str:
    ip, port, l4, proto = sig
    where = f"{ip}:{port}" if port is not None else ip
    proto_s = f" [{proto}]" if proto else ""
    return f"{l4} {where}{proto_s}"


@dataclass
class SignatureAgg:
    packets: int = 0
    bytes: int = 0


@dataclass
class Comparison:
    labels: list[str]
    camera_ip: Optional[str]
    # signature -> label -> aggregate
    signatures: dict[Signature, dict[str, SignatureAgg]] = field(default_factory=dict)
    dns_by_label: dict[str, set[str]] = field(default_factory=dict)
    sni_by_label: dict[str, set[str]] = field(default_factory=dict)

    def labels_for(self, sig: Signature) -> set[str]:
        return set(self.signatures.get(sig, {}).keys())

    def unique_signatures(self) -> dict[str, list[Signature]]:
        """Signatures that appear in exactly one label."""
        out: dict[str, list[Signature]] = {lbl: [] for lbl in self.labels}
        for sig, per in self.signatures.items():
            if len(per) == 1:
                (lbl,) = per.keys()
                out[lbl].append(sig)
        return out

    def common_signatures(self) -> list[Signature]:
        """Signatures present in every label."""
        n = len(self.labels)
        return [sig for sig, per in self.signatures.items() if len(per) == n]

    def unique_dns(self) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        for lbl, names in self.dns_by_label.items():
            others: set[str] = set()
            for other, onames in self.dns_by_label.items():
                if other != lbl:
                    others |= onames
            out[lbl] = names - others
        return out


def compare_summaries(
    named: dict[str, Summary],
    camera_ip: Optional[str] = None,
) -> Comparison:
    """Build a :class:`Comparison` from label -> :class:`Summary`."""
    labels = list(named.keys())
    cmp = Comparison(labels=labels, camera_ip=camera_ip)

    for label, summary in named.items():
        cam = camera_ip or summary.camera_ip
        for conv in summary.conversations.values():
            sig = flow_signature(conv, cam)
            per = cmp.signatures.setdefault(sig, {})
            agg = per.setdefault(label, SignatureAgg())
            agg.packets += conv.packets
            agg.bytes += conv.bytes_total
        cmp.dns_by_label[label] = set(summary.dns_queries.keys())
        cmp.sni_by_label[label] = set(summary.sni_names.keys())

    return cmp
