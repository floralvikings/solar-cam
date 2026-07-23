"""Tests for p4p.session request/response (synthetic; verified layout)."""

from __future__ import annotations

import socket
import struct

from p4p.crypto import decode, encode
from p4p.packet import MAGIC, parse_plain
from p4p.session import (
    build_lanstreamreq,
    make_random_id,
    parse_lanstreamrsp,
)

DUMMY_UID = "ABCDEFGHIJKLMNOP1234"


def test_lanstreamreq_header_and_uid():
    wire = build_lanstreamreq(DUMMY_UID)
    assert len(wire) == 16 + 108
    pkt = parse_plain(decode(wire))
    assert pkt.msgtype == 0x1307
    assert pkt.aux == 0x21
    assert pkt.payload_len == 108
    assert pkt.body[0] == 0x01
    assert pkt.body[24:44] == DUMMY_UID.encode()


def test_parse_lanstreamrsp_extracts_endpoint():
    # Build a synthetic 0x1308 the way the camera does.
    body = bytearray(452)
    body[12:16] = socket.inet_aton("192.168.88.113")
    struct.pack_into(">H", body, 16, 53568)          # port, network order
    struct.pack_into("<I", body, 24, 0x0000F82B)     # session id
    body[28:48] = DUMMY_UID.encode()
    header = MAGIC + struct.pack("<HHHH", len(body), 0, 0x1308, 0x12) + b"\x00\x00\x00\x00"
    wire = encode(header + bytes(body))

    rsp = parse_lanstreamrsp(decode(wire))
    assert rsp.camera_ip == "192.168.88.113"
    assert rsp.session_port == 53568
    assert rsp.session_id == 0x0000F82B
    assert rsp.uid == DUMMY_UID


def test_make_random_id_deterministic_from_seed():
    assert make_random_id(b"\x01\x02\x03\x04") == 0x04030201
    assert 0 <= make_random_id(b"\xff\xff\xff\xff") <= 0xFFFFFFFF


def test_build_alive_carries_conv():
    from p4p.crypto import decode
    from p4p.packet import parse_plain
    from p4p.session import build_alive
    wire = build_alive(0xD8FD6437)
    pkt = parse_plain(decode(wire))
    assert pkt.msgtype == 0x1405
    assert pkt.aux == 0x21
    assert pkt.body[:2] == b"\x07\x00"           # channels 0x0007
    assert pkt.body[8:12] == b"\x37\x64\xfd\xd8"  # conv LE


def test_build_kcp_ack_roundtrip():
    from p4p.crypto import decode
    from p4p.packet import parse_plain
    from p4p.session import build_kcp_ack, parse_kcp_segment
    wire = build_kcp_ack(0x11223344, sn=5, una=6)
    pkt = parse_plain(decode(wire))
    assert pkt.msgtype == 0x1409 and pkt.aux == 0x21
    seg = parse_kcp_segment(pkt.body)
    assert seg["conv"] == 0x11223344 and seg["cmd"] == 82
    assert seg["sn"] == 5 and seg["una"] == 6
