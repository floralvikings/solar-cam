"""Unit tests for pcaptools.analyze (pure logic, no tshark)."""

from __future__ import annotations

from pcaptools.analyze import (
    guess_camera_ip,
    high_bandwidth_flows,
    is_private_ip,
    shannon_entropy,
    size_bucket,
    suspected_keepalives,
    summarize,
)
from pcaptools.model import PacketRow

CAM = "192.168.50.42"
CLOUD = "203.0.113.9"


def _p(n, t, length, src, dst, sport, dport, l4="udp", proto=None, **kw):
    return PacketRow(
        number=n,
        time=t,
        length=length,
        src=src,
        dst=dst,
        l4=l4,
        srcport=sport,
        dstport=dport,
        protocol=proto,
        **kw,
    )


def test_is_private_ip():
    assert is_private_ip("192.168.1.1")
    assert is_private_ip("10.0.0.5")
    assert not is_private_ip("8.8.8.8")
    assert not is_private_ip(None)
    assert not is_private_ip("not-an-ip")


def test_size_bucket_boundaries():
    assert size_bucket(0) == "0-63"
    assert size_bucket(63) == "0-63"
    assert size_bucket(64) == "64-127"
    assert size_bucket(1471) == "1024-1471"
    assert size_bucket(1472) == "1472+"
    assert size_bucket(9000) == "1472+"


def test_shannon_entropy_extremes():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 100) == 0.0  # constant -> 0 bits
    # All 256 byte values once each -> 8 bits/byte
    assert abs(shannon_entropy(bytes(range(256))) - 8.0) < 1e-9


def test_summarize_basic_counts_and_ports():
    rows = [
        _p(1, 100.0, 100, CAM, CLOUD, 40000, 8000, proto="UDP"),
        _p(2, 100.5, 1200, CLOUD, CAM, 8000, 40000, proto="UDP"),
        _p(3, 101.0, 80, CAM, "8.8.8.8", 5353, 53, proto="DNS",
           dns_query="api.example.com", dns_answers=("203.0.113.9",)),
    ]
    s = summarize(rows, camera_ip=CAM)
    assert s.packet_count == 3
    assert s.total_bytes == 1380
    assert s.duration == 1.0
    assert s.protocol_counts["UDP"] == 2
    assert s.protocol_counts["DNS"] == 1
    # server port = min(sport, dport)
    assert s.udp_ports[8000] == 2
    assert s.udp_ports[53] == 1
    assert s.dns_queries["api.example.com"] == 1
    assert s.dns_answers["api.example.com"] == {"203.0.113.9"}
    # one bidirectional conversation for the 8000 flow, one for DNS
    assert len(s.conversations) == 2


def test_summarize_empty():
    s = summarize([], camera_ip=CAM)
    assert s.packet_count == 0
    assert s.duration == 0.0
    assert s.first_time == 0.0


def test_guess_camera_ip_picks_busiest_private():
    rows = [
        _p(1, 1.0, 100, CAM, CLOUD, 1, 2),
        _p(2, 1.1, 100, CLOUD, CAM, 2, 1),
        _p(3, 1.2, 100, CAM, "8.8.8.8", 1, 53),
    ]
    assert guess_camera_ip(rows) == CAM


def test_high_bandwidth_flow_detected():
    # 200 packets of ~1400B over 4s from cloud to camera -> video-like
    rows = []
    for i in range(200):
        rows.append(_p(i, 100.0 + i * 0.02, 1400, CLOUD, CAM, 8000, 40000, proto="RTP"))
    s = summarize(rows, camera_ip=CAM)
    hb = high_bandwidth_flows(s.conversations.values())
    assert len(hb) == 1
    assert hb[0].bytes_total == 200 * 1400


def test_keepalive_flow_detected():
    # small, regularly-spaced packets every 1s -> keepalive
    rows = []
    for i in range(20):
        rows.append(_p(i, 100.0 + i * 1.0, 60, CAM, CLOUD, 40000, 9000, proto="UDP"))
    s = summarize(rows, camera_ip=CAM)
    ka = suspected_keepalives(s.conversations.values())
    assert len(ka) == 1
    assert ka[0].packets == 20


def test_keepalive_ignores_bursty_bulk():
    # large packets -> not a keepalive
    rows = []
    for i in range(20):
        rows.append(_p(i, 100.0 + i * 1.0, 1400, CAM, CLOUD, 40000, 9000))
    s = summarize(rows, camera_ip=CAM)
    assert suspected_keepalives(s.conversations.values()) == []
