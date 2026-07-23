"""Tests for p4p.lansearch (request build + reply parse).

Reply parsing is tested against a *synthetic* reply we encode ourselves, using
a dummy UID/account/credential -- never a real device secret.
"""

from __future__ import annotations

import struct

import pytest

from p4p.crypto import encode
from p4p.lansearch import (
    LAN_SEARCH_PORT,
    build_lansearch_request,
    parse_lansearch_reply,
)
from p4p.packet import MAGIC

DUMMY_UID = "ABCDEFGHIJKLMNOP1234"


def test_port():
    assert LAN_SEARCH_PORT == 32762


def test_request_is_36_bytes_plaintext():
    req = build_lansearch_request(DUMMY_UID)
    assert len(req) == 36
    assert req[:4] == MAGIC
    assert int.from_bytes(req[4:6], "little") == 36        # total len
    assert req[6:8] == bytes([0x01, 0x13])                 # msgtype 0x1301
    assert req[8:28] == DUMMY_UID.encode()
    assert req[28] == 0x00
    assert req[-7:] == bytes([0xFE, 0x3D, 0x03, 0x00, 0x00, 0x00, 0x00])


@pytest.mark.parametrize("bad", ["SHORT", "", "A" * 21, "HAS-DASH-XXXXXXXXXX1"])
def test_request_rejects_bad_uid(bad):
    with pytest.raises(ValueError):
        build_lansearch_request(bad)


def _synthetic_reply(uid, account, credential):
    # Standard 16-byte header, msgtype 0x1302, body = uid(20) + \x01 pad + strings
    body = uid.encode().ljust(20, b"\x00")
    body += b"\x31" + b"\x00" * 16 + account.encode() + b"\x00" * 3
    body += b"\x00" * 8 + credential.encode() + b"\x00" * 4
    header = MAGIC + struct.pack("<HHHH", len(body), 0xA890, 0x1302, 0x12) + b"\x00\x00\x00\x00"
    return encode(header + body)  # obfuscated, as it arrives on the wire


def test_parse_reply_extracts_fields():
    from p4p.crypto import decode
    wire = _synthetic_reply(DUMMY_UID, "admin", "s3cr3t-token-XY")
    info = parse_lansearch_reply(decode(wire), src=("192.168.88.113", 32762))
    assert info.uid == DUMMY_UID
    assert info.account == "admin"
    assert info.credential == "s3cr3t-token-XY"
    assert info.source_ip == "192.168.88.113"


def test_parse_reply_masked_hides_credential():
    from p4p.crypto import decode
    wire = _synthetic_reply(DUMMY_UID, "admin", "s3cr3t-token-XY")
    info = parse_lansearch_reply(decode(wire)).masked()
    assert info.credential == "<15 chars>"
    assert info.account == "admin"       # account is not secret
    assert "s3cr3t-token-XY" not in (info.strings or [])


def test_parse_rejects_non_reply():
    from p4p.crypto import decode
    from p4p.packet import build, MsgType
    wire = build(MsgType.KEEPALIVE_REQ, b"\x00" * 20)
    with pytest.raises(ValueError):
        parse_lansearch_reply(decode(wire))
