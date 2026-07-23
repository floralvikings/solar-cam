"""Unit tests for the pure-Python KCP receiver and H.264 extraction."""

from __future__ import annotations

import struct

from p4p.client import extract_h264
from p4p.kcp import KcpReceiver


def push(conv, sn, frg, data, ts=0):
    return struct.pack("<IBBHIIII", conv, 81, frg, 256, ts, sn, 0, len(data)) + data


def test_single_segment_message():
    r = KcpReceiver(0x1234)
    r.input(push(0x1234, 0, 0, b"hello"))
    assert r.messages() == [b"hello"]
    assert r.rcv_nxt == 1


def test_fragmented_message_reassembles():
    r = KcpReceiver(0x1234)
    r.input(push(0x1234, 0, 2, b"AB"))   # frg counts down: 2,1,0
    r.input(push(0x1234, 1, 1, b"CD"))
    assert r.messages() == []            # not complete yet
    r.input(push(0x1234, 2, 0, b"EF"))
    assert r.messages() == [b"ABCDEF"]


def test_out_of_order_and_dedup():
    r = KcpReceiver(0x1234)
    r.input(push(0x1234, 1, 0, b"world"))
    assert r.messages() == []            # waiting for sn 0
    r.input(push(0x1234, 0, 0, b"hello"))
    r.input(push(0x1234, 0, 0, b"hello"))  # duplicate ignored
    assert r.messages() == [b"hello", b"world"]


def test_ignores_wrong_conv():
    r = KcpReceiver(0x1234)
    r.input(push(0x9999, 0, 0, b"nope"))
    assert r.messages() == []


def test_multiple_segments_packed_in_one_input():
    r = KcpReceiver(0x1234)
    r.input(push(0x1234, 0, 0, b"aa") + push(0x1234, 1, 0, b"bb"))
    assert r.messages() == [b"aa", b"bb"]


def test_ack_segments():
    r = KcpReceiver(0x1234)
    r.input(push(0x1234, 0, 0, b"x", ts=99))
    r.messages()
    acks = r.ack_segments()
    assert len(acks) == 1
    conv, cmd, frg, wnd, ts, sn, una, ln = struct.unpack("<IBBHIIII", acks[0])
    assert cmd == 82 and conv == 0x1234 and sn == 0 and una == 1 and ts == 99
    assert r.ack_segments() == []  # cleared


def test_extract_h264_video_only():
    # video message: type 0x11, 32-byte header, then Annex-B H.264
    vid = b"\x11" + b"\x00" * 31 + b"\x00\x00\x00\x01\x67rest"
    got = extract_h264(vid)
    assert got == b"\x00\x00\x00\x01\x67rest"
    # audio message (type 0x13) is skipped
    assert extract_h264(b"\x13" + b"\xff" * 40) is None
    # no start code -> skipped
    assert extract_h264(b"\x11" + b"\x00" * 40) is None
