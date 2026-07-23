"""Tests for p4p.packet framing (16-byte header + obfuscation)."""

from __future__ import annotations

import struct

import pytest

from p4p.crypto import decode
from p4p.packet import MAGIC, MsgType, Packet, build, parse, parse_plain


def test_build_has_magic_and_roundtrips():
    body = b"hello-body-1234"
    wire = build(MsgType.IOCTRL_REQ, body)
    # wire is obfuscated; deobfuscating must reveal the header + body
    plain = decode(wire)
    assert plain[:4] == MAGIC
    pkt = parse(wire)
    assert pkt.msgtype == MsgType.IOCTRL_REQ
    assert pkt.body == body
    assert pkt.payload_len == len(body)


def test_header_field_layout():
    body = b"\xaa" * 10
    plain = decode(build(0x1234, body, flags=0x1, aux=0x2))
    paylen, flags, msgtype, aux = struct.unpack_from("<HHHH", plain, 4)
    assert paylen == 10
    assert flags == 1
    assert msgtype == 0x1234
    assert aux == 2
    assert plain[12:16] == b"\x00\x00\x00\x00"


def test_parse_plain_real_header():
    # A real deobfuscated cloud header (0x1101 session req), body zeroed out.
    plain = bytes.fromhex("07181000") + struct.pack("<HHHH", 4, 0, 0x1101, 0x14) + \
        b"\x00\x00\x00\x00" + b"BODY"
    pkt = parse_plain(plain)
    assert pkt.msgtype == 0x1101
    assert pkt.type_name == "SESSION_REQ"
    assert pkt.body == b"BODY"


def test_parse_rejects_bad_magic():
    with pytest.raises(ValueError):
        parse_plain(b"\x00\x00\x00\x00" + b"\x00" * 12)


def test_type_name_unknown():
    assert Packet(msgtype=0x9999, body=b"").type_name == "0x9999"
