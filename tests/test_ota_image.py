"""Unit tests for ota_image — the RBX-S73 OTA container format.

Every rule asserted here is transcribed from ``download_auto_update``
(``ubia_t23`` @0x41a98c); see docs/firmware-analysis.md for the disassembly.
"""

from __future__ import annotations

import struct

import pytest

from ota_image import (
    CRC_OFFSET,
    HEADER_LEN,
    OtaImageError,
    build,
    compute_crc,
    crc32_raw,
    crc32_raw_bitwise,
    header_crc_input,
    parse,
    payload_of,
    verify,
)

PAYLOAD = bytes(range(256)) * 8


# --- the CRC routine @0x4c1b14 ----------------------------------------------

def test_crc_matches_the_literal_bitwise_transcription():
    """The fast zlib form must agree with the instruction-for-instruction one."""
    for data in (b"", b"1", b"123456789", PAYLOAD, bytes(31)):
        assert crc32_raw(data) == crc32_raw_bitwise(data), data[:8]


def test_crc_has_no_initial_and_no_final_inversion():
    # v0 starts as the seed argument and is returned unmodified, so an empty
    # buffer with seed 0 must come back as 0 -- not 0xffffffff, and not the
    # standard CRC-32 of the empty string.
    assert crc32_raw(b"") == 0
    assert crc32_raw(b"", seed=0x12345678) == 0x12345678


def test_crc_seeding_is_equivalent_to_concatenation():
    """The firmware CRCs the header, then feeds that result in as the payload seed."""
    a, b = PAYLOAD[:100], PAYLOAD[100:]
    assert crc32_raw(b, seed=crc32_raw(a)) == crc32_raw(a + b)


# --- header layout ----------------------------------------------------------

def test_header_is_32_bytes_with_the_crc_in_the_last_word():
    assert HEADER_LEN == 32
    assert CRC_OFFSET == 0x1C


def test_crc_input_zeroes_word0_and_the_crc_word_only():
    header = bytes(range(32))
    masked = header_crc_input(header)
    assert masked[0:4] == b"\x00\x00\x00\x00"
    assert masked[CRC_OFFSET:CRC_OFFSET + 4] == b"\x00\x00\x00\x00"
    assert masked[4:CRC_OFFSET] == header[4:CRC_OFFSET]


def test_word0_is_outside_the_crc_so_editing_it_keeps_the_image_valid():
    image = bytearray(build(PAYLOAD))
    assert verify(bytes(image)).ok
    struct.pack_into("<I", image, 0, 0xDEADBEEF)
    assert verify(bytes(image)).ok, "word 0 is zeroed before hashing"


@pytest.mark.parametrize("offset", [4, 8, 12, 16, 20, 24])
def test_words_1_through_6_are_covered_by_the_crc(offset):
    image = bytearray(build(PAYLOAD))
    struct.pack_into("<I", image, offset, 0xDEADBEEF)
    assert not verify(bytes(image)).ok


def test_payload_is_covered_by_the_crc():
    image = bytearray(build(PAYLOAD))
    image[HEADER_LEN + 10] ^= 0xFF
    assert not verify(bytes(image)).ok


# --- what the device actually flashes ---------------------------------------

def test_payload_excludes_the_header():
    """SaveDownLoadFile gets (buf + 0x20, total - 0x20) -- the header is stripped."""
    image = build(PAYLOAD)
    assert payload_of(image) == PAYLOAD
    assert len(image) == len(PAYLOAD) + HEADER_LEN


def test_a_zero_crc_field_is_rejected():
    """`beqz $s7` @0x41c968 sends a zero stored CRC down the invalid-image path."""
    image = bytearray(build(PAYLOAD))
    struct.pack_into("<I", image, CRC_OFFSET, 0)
    result = verify(bytes(image))
    assert not result.ok
    assert "zero" in result.reason.lower()


# --- round trip / errors ----------------------------------------------------

def test_build_then_verify_round_trip():
    image = build(PAYLOAD, words=(0, 1, 2, 3, 4, 5, 6))
    result = verify(image)
    assert result.ok
    assert result.reason == ""
    header = parse(image)
    assert header.words[1:7] == (1, 2, 3, 4, 5, 6)
    assert header.crc == compute_crc(image)


def test_build_rejects_the_wrong_number_of_words():
    with pytest.raises(ValueError):
        build(PAYLOAD, words=(1, 2))


def test_build_rejects_an_empty_payload():
    with pytest.raises(ValueError):
        build(b"")


def test_parse_rejects_a_truncated_image():
    with pytest.raises(OtaImageError):
        parse(bytes(HEADER_LEN))
    with pytest.raises(OtaImageError):
        parse(bytes(8))
