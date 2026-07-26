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
