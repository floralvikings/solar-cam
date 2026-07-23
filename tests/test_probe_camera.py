"""Tests for the UBIA/TUTK LAN-search request builder.

The byte layout was recovered from a capture of the UBox app's startup
broadcast. A dummy UID is used here -- never commit a real device UID.
"""

from __future__ import annotations

import pytest

from probe_camera import (
    LAN_SEARCH_PORT,
    UID_LEN,
    build_lansearch_request,
)

DUMMY_UID = "ABCDEFGHIJKLMNOP1234"  # 20 chars, same shape as a real UID


def test_port_is_32762():
    assert LAN_SEARCH_PORT == 32762


def test_request_is_36_bytes():
    pkt = build_lansearch_request(DUMMY_UID)
    assert len(pkt) == 36


def test_length_field_matches_actual_length():
    pkt = build_lansearch_request(DUMMY_UID)
    declared = int.from_bytes(pkt[4:6], "little")
    assert declared == len(pkt) == 36


def test_fixed_header_and_tail():
    pkt = build_lansearch_request(DUMMY_UID)
    assert pkt[0:4] == bytes([0x07, 0x18, 0x10, 0x00])
    assert pkt[6:8] == bytes([0x01, 0x13])
    assert pkt[-7:] == bytes([0xFE, 0x3D, 0x03, 0x00, 0x00, 0x00, 0x00])


def test_uid_embedded_ascii_null_terminated():
    pkt = build_lansearch_request(DUMMY_UID)
    assert pkt[8 : 8 + UID_LEN] == DUMMY_UID.encode("ascii")
    assert pkt[8 + UID_LEN] == 0x00


def test_uid_is_uppercased():
    lower = build_lansearch_request(DUMMY_UID.lower())
    upper = build_lansearch_request(DUMMY_UID)
    assert lower == upper


@pytest.mark.parametrize("bad", ["TOOSHORT", "", "A" * 21, "HAS-DASH-IN-IT-1234"])
def test_invalid_uid_rejected(bad):
    with pytest.raises(ValueError):
        build_lansearch_request(bad)
