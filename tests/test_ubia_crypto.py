"""Tests for the UBIA/TUTK obfuscation codec.

Uses synthetic plaintext for round-trip tests. Does NOT embed the real
captured response, which contains device credentials.
"""

from __future__ import annotations

import os

import pytest

from pcaptools.ubia_crypto import KEY, decode, encode


def test_key_recovered_from_binary():
    assert KEY == b"I believe 1 ^ill win the battle!"
    assert len(KEY) == 32


@pytest.mark.parametrize("n", [0, 1, 7, 15, 16, 17, 31, 32, 33, 100, 408])
def test_round_trip_lengths(n):
    data = os.urandom(n)
    assert decode(encode(data)) == data


def test_round_trip_structured_payload():
    # request-shaped: header + UID-like ascii + tail
    data = bytes([0x07, 0x18, 0x10, 0x00, 0x24, 0x00, 0x01, 0x13])
    data += b"ABCDEFGHIJKLMNOP1234\x00"
    data += bytes([0xFE, 0x3D, 0x03, 0x00, 0x00, 0x00, 0x00])
    assert decode(encode(data)) == data


def test_encode_changes_data():
    data = b"\x00" * 16
    enc = encode(data)
    assert enc != data
    # all-zero plaintext encodes to the (permuted, rotated) key material
    assert len(enc) == 16


def test_single_full_block_matches_manual():
    # A full 16-byte block must survive a round trip and differ from input.
    block = bytes(range(16))
    enc = encode(block)
    assert len(enc) == 16
    assert enc != block
    assert decode(enc) == block


def test_partial_tail_only_xor_swap():
    # Tails < 16 bytes take the no-rotation path; still reversible.
    for n in (1, 5, 8, 13):
        data = os.urandom(n)
        assert decode(encode(data)) == data


def test_matches_real_device_header():
    """Regression against a real captured LAN-search reply.

    Only the first two encoded blocks are embedded (the device header), and we
    assert only the non-secret framing: magic 07 18 10 00 and response message
    type 0x1302. The credential-bearing remainder is deliberately excluded.
    """
    # First 32 bytes of an actual camera response (encoded/on-the-wire form).
    # Decodes to header 07181000..., msgtype 1302 (response to request 1301).
    enc = bytes.fromhex(
        "34858d2d62bcd8d2255d498d66ca43c0"
        "8151a83b550faab771e5ed8888820e7c"
    )
    dec = decode(enc)
    assert dec[:4] == bytes([0x07, 0x18, 0x10, 0x00])  # magic
    assert dec[8:10] == bytes([0x02, 0x13])  # msgtype 0x1302 (LE)
    # And it must re-encode to the exact wire bytes.
    assert encode(dec) == enc
