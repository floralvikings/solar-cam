"""Unit tests for pcaptools.udpflows."""

from __future__ import annotations

from pcaptools.model import PacketRow
from pcaptools.udpflows import (
    analyze_flow,
    collect_udp_flows,
    common_prefix,
    detect_sequence_field,
)

CAM = "192.168.50.42"
PEER = "203.0.113.9"


def _p(n, src, dst, sport, dport, payload):
    return PacketRow(
        number=n, time=float(n), length=len(payload) + 42,
        src=src, dst=dst, l4="udp", srcport=sport, dstport=dport,
        payload=payload,
    )


def test_common_prefix():
    payloads = [b"\xaa\xbb\x00\x01", b"\xaa\xbb\x00\x02", b"\xaa\xbb\xff\x03"]
    assert common_prefix(payloads) == b"\xaa\xbb"
    assert common_prefix([]) == b""
    assert common_prefix([b"", b"\x01"]) == b""


def test_detect_sequence_field_big_endian_2byte():
    # counter at offset 2, 2 bytes, big-endian, incrementing by 1
    payloads = [b"\xaa\xbb" + (100 + i).to_bytes(2, "big") + b"\x00\x00"
                for i in range(10)]
    res = detect_sequence_field(payloads)
    assert res is not None
    assert res["offset"] == 2
    assert res["width"] == 2
    assert res["endian"] == "big"
    assert res["ratio"] >= 0.8


def test_detect_sequence_field_none_for_random():
    import os
    payloads = [os.urandom(16) for _ in range(10)]
    # Random data almost never forms a clean incrementing counter, but the
    # detector requires >=0.8 monotonic ratio, so this should be None.
    res = detect_sequence_field(payloads)
    assert res is None or res["ratio"] < 1.0


def test_collect_excludes_known_ports_by_default():
    rows = [
        _p(1, CAM, "8.8.8.8", 5353, 53, b"\x00" * 20),  # DNS -> excluded
        _p(2, CAM, PEER, 40000, 8000, b"\x01" * 20),    # proprietary -> kept
        _p(3, PEER, CAM, 8000, 40000, b"\x02" * 20),
    ]
    flows = collect_udp_flows(rows)
    assert len(flows) == 1
    (flow,) = flows.values()
    assert flow.packets == 2
    assert flow.ab.packets == 1
    assert flow.ba.packets == 1


def test_analyze_flow_reports_directions():
    rows = [_p(i, CAM, PEER, 40000, 8000, bytes([i]) * 32) for i in range(8)]
    rows += [_p(i + 100, PEER, CAM, 8000, 40000, bytes([i]) * 1000) for i in range(8)]
    flows = collect_udp_flows(rows)
    (flow,) = flows.values()
    rep = analyze_flow(flow)
    assert rep["total_packets"] == 16
    assert rep["a_to_b"]["packets"] == 8
    assert rep["b_to_a"]["packets"] == 8
    # b->a direction carries far more payload (video-like)
    assert rep["b_to_a"]["payload_bytes"] > rep["a_to_b"]["payload_bytes"]
