"""Dev-only P4P ioctrl helpers for the research probes.

These (KcpSender + the type-3 ioctrl frame) were removed from the shipped p4p
package when local PTZ/ioctrl proved cloud-gated. They live here so the probes
in tools/ still run without re-adding dead code to the HA integration.
NOT imported by the integration. No secrets.
"""
from __future__ import annotations
import struct

_HDR = struct.Struct("<IBBHIIII")
IKCP_CMD_PUSH = 81
IKCP_CMD_ACK = 82
IKCP_RCV_WND = 256


class KcpSender:
    """Minimal client->device KCP PUSH sender (no congestion control)."""

    def __init__(self, conv: int, wnd: int = IKCP_RCV_WND) -> None:
        self.conv = conv & 0xFFFFFFFF
        self.wnd = wnd
        self.snd_nxt = 0
        self.unacked: dict[int, bytes] = {}

    def push(self, payload: bytes, *, una: int = 0, ts: int = 0) -> bytes:
        sn = self.snd_nxt
        seg = _HDR.pack(self.conv, IKCP_CMD_PUSH, 0, self.wnd, ts, sn, una, len(payload)) + payload
        self.snd_nxt += 1
        self.unacked[sn] = seg
        return seg

    def note_acks(self, udp_payload: bytes) -> list[int]:
        data = udp_payload
        off = 0
        n = len(data)
        acked: list[int] = []
        while n - off >= _HDR.size:
            conv, cmd, frg, wnd, ts, sn, una, ln = _HDR.unpack_from(data, off)
            off += _HDR.size + ln
            if conv != self.conv:
                continue
            for x in [k for k in self.unacked if k < una]:
                del self.unacked[x]; acked.append(x)
            if cmd == IKCP_CMD_ACK and sn in self.unacked:
                del self.unacked[sn]; acked.append(sn)
        return acked

    def retransmit_segments(self) -> list[bytes]:
        return list(self.unacked.values())


def build_ioctrl_frame(avchannel: int, iotype: int, data: bytes) -> bytes:
    """Type-3 ioctrl frame: [0:2]=3 [2]=avchannel [8:12]=datalen [0xc:0x10]=iotype [0x10:]=data."""
    f = bytearray(0x10 + len(data))
    struct.pack_into("<H", f, 0, 3)
    f[2] = avchannel & 0xFF
    struct.pack_into("<I", f, 8, len(data))
    struct.pack_into("<I", f, 0xC, iotype & 0xFFFFFFFF)
    f[0x10:] = data
    return bytes(f)
