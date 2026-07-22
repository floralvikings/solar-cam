"""Unit tests for pcaptools.compare."""

from __future__ import annotations

from pcaptools.analyze import summarize
from pcaptools.compare import compare_summaries, flow_signature
from pcaptools.model import PacketRow

CAM = "192.168.50.42"
CLOUD_A = "203.0.113.9"
CLOUD_B = "198.51.100.7"


def _p(n, src, dst, sport, dport, proto="UDP", length=100):
    return PacketRow(
        number=n, time=float(n), length=length, src=src, dst=dst,
        l4="udp", srcport=sport, dstport=dport, protocol=proto,
    )


def _summary(label_rows, camera_ip=CAM):
    return summarize(label_rows, camera_ip=camera_ip)


def test_flow_signature_drops_camera_ephemeral_port():
    # Same remote flow, different camera ephemeral ports -> same signature.
    c1 = summarize([_p(1, CAM, CLOUD_A, 40000, 8000)], camera_ip=CAM)
    c2 = summarize([_p(1, CAM, CLOUD_A, 55555, 8000)], camera_ip=CAM)
    (conv1,) = c1.conversations.values()
    (conv2,) = c2.conversations.values()
    assert flow_signature(conv1, CAM) == flow_signature(conv2, CAM)
    assert flow_signature(conv1, CAM)[0] == CLOUD_A
    assert flow_signature(conv1, CAM)[1] == 8000


def test_compare_identifies_unique_and_common():
    idle = _summary([_p(1, CAM, CLOUD_A, 40000, 9000, proto="UDP")])  # keepalive
    live = _summary([
        _p(1, CAM, CLOUD_A, 40001, 9000, proto="UDP"),   # same keepalive
        _p(2, CAM, CLOUD_B, 50000, 8000, proto="RTP"),   # NEW video flow
    ])
    cmp = compare_summaries({"idle": idle, "live": live}, camera_ip=CAM)

    common = cmp.common_signatures()
    assert (CLOUD_A, 9000, "udp", "UDP") in common

    unique = cmp.unique_signatures()
    assert unique["idle"] == []
    assert (CLOUD_B, 8000, "udp", "RTP") in unique["live"]


def test_compare_unique_dns():
    idle = _summary([])
    idle.dns_queries["keepalive.example.com"] = 1
    live = _summary([])
    live.dns_queries["keepalive.example.com"] = 1
    live.dns_queries["stream.example.com"] = 1

    cmp = compare_summaries({"idle": idle, "live": live}, camera_ip=CAM)
    udns = cmp.unique_dns()
    assert udns["live"] == {"stream.example.com"}
    assert udns["idle"] == set()
