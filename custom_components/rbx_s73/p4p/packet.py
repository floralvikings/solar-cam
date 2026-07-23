"""P4P packet framing.

Two framings observed (see docs/protocol-notes.md, verified from real bytes):

* **Standard messages** (all session/cloud traffic, and the LAN-search reply) —
  a 16-byte header, and the *whole packet is obfuscated* with :mod:`p4p.crypto`:

      magic(4) | payload_len(u16 LE, = total-16) | flags(u16) |
      msgtype(u16 LE) | aux(u16) | reserved(u32) | body...

* **LAN-search request** — a compact 8-byte header, sent *in plaintext*
  (built in :mod:`p4p.lansearch`):

      magic(4) | total_len(u16 LE) | msgtype(u16 LE) | body...
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

from .crypto import decode as _deobfuscate
from .crypto import encode as _obfuscate

MAGIC = b"\x07\x18\x10\x00"
HEADER_LEN = 16


class MsgType(IntEnum):
    # --- Confirmed on the wire ---
    LAN_SEARCH_REQ = 0x1301
    LAN_SEARCH_RSP = 0x1302
    LOOKUP_REQ = 0x1001       # camera<->cloud rendezvous (UDP 10240)
    LOOKUP_RSP = 0x1002
    SESSION_REQ = 0x1101      # camera<->cloud session (UDP 20001)
    SESSION_RSP = 0x1102
    PEER_EXCH_REQ = 0x1105    # LAN/WAN peer address exchange (hole-punch)
    PEER_EXCH_RSP = 0x1106
    KEEPALIVE_REQ = 0x1406
    KEEPALIVE_RSP = 0x1409
    DATA = 0x140A             # bulk/media upload
    CLI_LOOKUP_REQ = 0x1051   # phone(client)<->cloud
    CLI_LOOKUP_RSP = 0x1052
    CLI_SESSION_REQ = 0x1201
    CLI_SESSION_RSP = 0x1202
    # --- Candidate (from SDK disassembly; verify empirically) ---
    IOCTRL_REQ = 0x1401       # send_ioctrl (AVIOCTRLDEFs opcodes)
    IOCTRL_RSP = 0x1402
    LAN_STREAM_REQ = 0x1307   # send_lanstreamreq
    RLY_STREAM_REQ = 0x1205   # send_rlystreamreq
    PRECONNECT = 0x110A       # preconnect/PUNCH2LAN


@dataclass(frozen=True)
class Packet:
    msgtype: int
    body: bytes
    flags: int = 0
    aux: int = 0
    payload_len: int | None = None

    @property
    def type_name(self) -> str:
        try:
            return MsgType(self.msgtype).name
        except ValueError:
            return f"0x{self.msgtype:04x}"


def build(msgtype: int, body: bytes = b"", *, flags: int = 0, aux: int = 0) -> bytes:
    """Build and obfuscate a standard 16-byte-header P4P packet (ready to send)."""
    header = MAGIC + struct.pack("<HHHH", len(body), flags, msgtype, aux) + b"\x00\x00\x00\x00"
    return _obfuscate(header + body)


def parse_plain(decoded: bytes) -> Packet:
    """Parse an already-deobfuscated standard packet."""
    if decoded[:4] != MAGIC:
        raise ValueError(f"bad P4P magic: {decoded[:4].hex()}")
    if len(decoded) < HEADER_LEN:
        raise ValueError("packet shorter than header")
    payload_len, flags, msgtype, aux = struct.unpack_from("<HHHH", decoded, 4)
    body = decoded[HEADER_LEN:]
    # payload_len should equal len(body); tolerate padding/truncation.
    if payload_len and payload_len <= len(body):
        body = body[:payload_len]
    return Packet(msgtype=msgtype, body=body, flags=flags, aux=aux, payload_len=payload_len)


def parse(wire: bytes) -> Packet:
    """Deobfuscate and parse a standard packet received off the wire."""
    return parse_plain(_deobfuscate(wire))
