"""Minimal pure-Python KCP (ikcp) receiver for the RBX-S73 AV stream.

The camera PUSHes video/audio over KCP inside obfuscated P4P 0x140a frames; the
client only needs to *receive* (reassemble fragmented messages) and *ACK* (so
the camera's send window keeps advancing). This is a focused receive-only
implementation -- no retransmit/congestion logic, which the client side doesn't
need -- and is pure Python so it runs anywhere (incl. a Home Assistant add-on /
HACS integration) with no native build.

KCP segment header (little-endian, 24 bytes):
    conv(u32) cmd(u8) frg(u8) wnd(u16) ts(u32) sn(u32) una(u32) len(u32)
A message may be fragmented into several segments with frg counting down to 0
(the last fragment). Multiple segments may be packed into one UDP payload.
"""

from __future__ import annotations

import struct

IKCP_CMD_PUSH = 81
IKCP_CMD_ACK = 82
IKCP_CMD_WASK = 83
IKCP_CMD_WINS = 84
IKCP_RCV_WND = 256
_HDR = struct.Struct("<IBBHIIII")


class KcpReceiver:
    """Receive-only KCP keyed by ``conv``."""

    def __init__(self, conv: int, wnd: int = IKCP_RCV_WND):
        self.conv = conv & 0xFFFFFFFF
        self.wnd = wnd
        self.rcv_nxt = 0
        self.rcv_buf: dict[int, tuple[int, bytes]] = {}  # sn -> (frg, data)
        self._acks: list[tuple[int, int]] = []            # (sn, ts) pending

    def input(self, udp_payload: bytes) -> None:
        """Feed one deobfuscated 0x140a body (may pack several KCP segments)."""
        data = udp_payload
        off = 0
        n = len(data)
        while n - off >= _HDR.size:
            conv, cmd, frg, wnd, ts, sn, una, ln = _HDR.unpack_from(data, off)
            off += _HDR.size
            body = data[off : off + ln]
            off += ln
            if conv != self.conv:
                continue
            if cmd == IKCP_CMD_PUSH:
                self._acks.append((sn, ts))
                if self.rcv_nxt <= sn < self.rcv_nxt + self.wnd and sn not in self.rcv_buf:
                    self.rcv_buf[sn] = (frg, body)

    def messages(self) -> list[bytes]:
        """Return all complete reassembled messages, advancing rcv_nxt."""
        out: list[bytes] = []
        while self.rcv_nxt in self.rcv_buf:
            nfrag = self.rcv_buf[self.rcv_nxt][0]  # frg of first segment = count-1
            need = [self.rcv_nxt + i for i in range(nfrag + 1)]
            if not all(s in self.rcv_buf for s in need):
                break  # message not fully arrived yet
            out.append(b"".join(self.rcv_buf[s][1] for s in need))
            for s in need:
                del self.rcv_buf[s]
            self.rcv_nxt = need[-1] + 1
        return out

    def ack_segments(self) -> list[bytes]:
        """Build KCP ACK segments for pending pushes (and clear the queue)."""
        segs = [
            _HDR.pack(self.conv, IKCP_CMD_ACK, 0, self.wnd, ts, sn, self.rcv_nxt, 0)
            for sn, ts in self._acks
        ]
        self._acks.clear()
        return segs

    @property
    def has_pending_acks(self) -> bool:
        return bool(self._acks)


class KcpSender:
    """Minimal client->device KCP PUSH sender (no congestion control).

    ioctrl commands ride the avchn's KCP reliable channel (same conv as the video
    stream, opposite direction). ``p4p_client_send_ioctrl`` builds a type-3 frame
    and hands it to ``p4p_kcp_send``; on the wire each segment is a 24-byte ikcp
    header + payload, wrapped in an obfuscated 0x1409 P4P packet (same wrapper as
    our video ACKs). Messages are tiny (<< MSS) so we never fragment (frg=0).
    """

    def __init__(self, conv: int, wnd: int = IKCP_RCV_WND):
        self.conv = conv & 0xFFFFFFFF
        self.wnd = wnd
        self.snd_nxt = 0
        self.unacked: dict[int, bytes] = {}  # sn -> segment bytes

    def push(self, payload: bytes, *, una: int = 0, ts: int = 0) -> bytes:
        """Allocate the next sn and return a single-fragment PUSH segment.

        ``una`` cumulatively acks the peer's send stream (pass the receiver's
        ``rcv_nxt``). The segment is remembered for retransmit until acked."""
        sn = self.snd_nxt
        seg = _HDR.pack(self.conv, IKCP_CMD_PUSH, 0, self.wnd, ts, sn, una, len(payload)) + payload
        self.snd_nxt += 1
        self.unacked[sn] = seg
        return seg

    def note_acks(self, udp_payload: bytes) -> list[int]:
        """Scan a deobfuscated 0x140a/0x1409 body for KCP ACKs of our pushes.

        Removes acked segments from the retransmit set; returns the acked sns.
        Honors both explicit ACK segments (cmd 82, sn) and the cumulative ``una``
        carried on any segment."""
        data = udp_payload
        off = 0
        n = len(data)
        acked: list[int] = []
        while n - off >= _HDR.size:
            conv, cmd, frg, wnd, ts, sn, una, ln = _HDR.unpack_from(data, off)
            off += _HDR.size + ln
            if conv != self.conv:
                continue
            for s in [k for k in self.unacked if k < una]:
                del self.unacked[s]; acked.append(s)
            if cmd == IKCP_CMD_ACK and sn in self.unacked:
                del self.unacked[sn]; acked.append(sn)
        return acked

    def retransmit_segments(self) -> list[bytes]:
        """All still-unacked segments (caller decides cadence)."""
        return list(self.unacked.values())


def build_ioctrl_frame(avchannel: int, iotype: int, data: bytes) -> bytes:
    """The type-3 ioctrl frame p4p_client_send_ioctrl feeds to KCP:
    [0:2]=3  [2]=avchannel  [3:8]=0  [8:12]=datalen  [0xc:0x10]=iotype  [0x10:]=data."""
    f = bytearray(0x10 + len(data))
    struct.pack_into("<H", f, 0, 3)
    f[2] = avchannel & 0xFF
    struct.pack_into("<I", f, 8, len(data))
    struct.pack_into("<I", f, 0xC, iotype & 0xFFFFFFFF)
    f[0x10:] = data
    return bytes(f)
