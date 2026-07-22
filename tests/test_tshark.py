"""Tests for pcaptools.tshark.

Includes a real end-to-end test against a hand-built pcap (skipped if
tshark is not installed) so the actual tshark invocation and field parsing
are exercised, not just the line splitter.
"""

from __future__ import annotations

import shutil
import socket
import struct

import pytest

from pcaptools import tshark
from pcaptools.tshark import _parse_line, find_tshark


def test_parse_line_udp_dns():
    fields = [
        "5", "1600000000.123", "74", "DNS",
        "192.168.50.42", "8.8.8.8", "", "", "17",
        "5555", "53", "", "",
        "example.com", "", "", "", "",
    ]
    row = _parse_line("\t".join(fields), include_payload=False)
    assert row is not None
    assert row.number == 5
    assert row.time == 1600000000.123
    assert row.length == 74
    assert row.protocol == "DNS"
    assert row.src == "192.168.50.42"
    assert row.dst == "8.8.8.8"
    assert row.l4 == "udp"
    assert row.srcport == 5555
    assert row.dstport == 53
    assert row.dns_query == "example.com"


def test_parse_line_tcp_with_sni():
    fields = [
        "9", "1600000001.0", "200", "TLSv1.2",
        "10.0.0.5", "203.0.113.9", "", "", "6",
        "", "", "51000", "443",
        "", "", "", "", "api.vendor-cloud.com",
    ]
    row = _parse_line("\t".join(fields), include_payload=False)
    assert row is not None
    assert row.l4 == "tcp"
    assert row.srcport == 51000
    assert row.dstport == 443
    assert row.sni == "api.vendor-cloud.com"


def test_parse_line_empty_returns_none():
    assert _parse_line("", include_payload=False) is None


def test_find_tshark_missing_raises():
    with pytest.raises(tshark.TsharkNotFound):
        find_tshark("/nonexistent/path/to/tshark")


# --- integration: build a minimal pcap and run real tshark on it ---

def _udp_packet(src_ip, dst_ip, sport, dport, payload):
    eth = bytes.fromhex("112233445566aabbccddeeff") + b"\x08\x00"
    udp_len = 8 + len(payload)
    udp = struct.pack(">HHHH", sport, dport, udp_len, 0) + payload
    total_len = 20 + udp_len
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0x00, total_len, 0, 0, 64, 17, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    return eth + ip + udp


def _dns_query(name="example.com"):
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    q = b""
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return header + q


def _write_pcap(path, packets):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, pkt in enumerate(packets):
            f.write(struct.pack("<IIII", 1600000000 + i, 0, len(pkt), len(pkt)))
            f.write(pkt)


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
def test_read_packets_integration(tmp_path):
    pcap = tmp_path / "mini.pcap"
    packets = [
        _udp_packet("192.168.50.42", "8.8.8.8", 5555, 53, _dns_query("example.com")),
        _udp_packet("192.168.50.42", "203.0.113.9", 40000, 8000,
                    b"\xaa\xbb\x00\x01ABCD"),
    ]
    _write_pcap(str(pcap), packets)

    rows = list(tshark.read_packets(str(pcap), include_payload=True))
    assert len(rows) == 2

    dns_row = next(r for r in rows if r.dstport == 53)
    assert dns_row.protocol == "DNS"
    assert dns_row.dns_query == "example.com"
    assert dns_row.src == "192.168.50.42"
    assert dns_row.l4 == "udp"

    data_row = next(r for r in rows if r.dstport == 8000)
    assert data_row.payload == b"\xaa\xbb\x00\x01ABCD"
    assert data_row.dst == "203.0.113.9"


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
def test_read_packets_bad_file_raises(tmp_path):
    bad = tmp_path / "not.pcap"
    bad.write_text("this is not a pcap")
    with pytest.raises(tshark.TsharkError):
        list(tshark.read_packets(str(bad)))
