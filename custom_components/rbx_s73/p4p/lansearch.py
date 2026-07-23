"""LAN discovery for UBIA/TUTK devices (UDP 32762).

The client broadcasts a plaintext 36-byte request naming the device UID; the
camera replies (obfuscated) with a ``LanSearchInfo`` record. This is the first
leg of a cloud-free session and is fully verified against the real device.
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field

from .crypto import decode as _deobfuscate
from .packet import MAGIC, MsgType, parse_plain

LAN_SEARCH_PORT = 32762
UID_LEN = 20

# Compact plaintext request framing (see docs/protocol-notes.md):
#   magic(4) | total_len(u16 LE) | msgtype 0x1301 | uid(20) 00 | fe 3d 03 00*4
_REQ_TYPE = bytes([0x01, 0x13])            # 0x1301 LE
_REQ_TAIL = bytes([0xFE, 0x3D, 0x03, 0x00, 0x00, 0x00, 0x00])


def build_lansearch_request(uid: str) -> bytes:
    uid = uid.strip().upper()
    if len(uid) != UID_LEN or not uid.isalnum():
        raise ValueError(f"UID must be {UID_LEN} alphanumeric chars, got {uid!r}")
    body = uid.encode("ascii") + b"\x00" + _REQ_TAIL
    total = 4 + 2 + 2 + len(body)
    return MAGIC + total.to_bytes(2, "little") + _REQ_TYPE + body


@dataclass
class LanSearchInfo:
    """Parsed camera reply to a LAN search."""

    uid: str
    account: str | None
    credential: str | None
    source_ip: str | None = None
    source_port: int | None = None
    strings: list[str] = field(default_factory=list)
    raw_body: bytes = b""

    def masked(self) -> "LanSearchInfo":
        """A copy safe to log: UID kept, credential redacted."""
        cred = None if self.credential is None else f"<{len(self.credential)} chars>"
        return LanSearchInfo(
            uid=self.uid, account=self.account, credential=cred,
            source_ip=self.source_ip, source_port=self.source_port,
            strings=[f"<{len(s)}>" if s == self.credential else s for s in self.strings],
        )


_ASCII_RUN = re.compile(rb"[\x20-\x7e]{2,}")


def parse_lansearch_reply(decoded: bytes, *, src: tuple[str, int] | None = None) -> LanSearchInfo:
    """Parse a deobfuscated LAN-search reply (msgtype 0x1302)."""
    pkt = parse_plain(decoded)
    if pkt.msgtype != MsgType.LAN_SEARCH_RSP:
        raise ValueError(f"not a LAN-search reply (msgtype 0x{pkt.msgtype:04x})")
    body = pkt.body
    uid = body[:UID_LEN].split(b"\x00", 1)[0].decode("ascii", "replace")
    # Remaining printable strings, in order: [account, credential, ...].
    tokens = [m.group().decode("ascii", "replace") for m in _ASCII_RUN.finditer(body[UID_LEN:])]
    account = tokens[0] if tokens else None
    credential = tokens[1] if len(tokens) > 1 else None
    return LanSearchInfo(
        uid=uid, account=account, credential=credential,
        source_ip=src[0] if src else None, source_port=src[1] if src else None,
        strings=tokens, raw_body=body,
    )


def discover(
    uid: str,
    *,
    targets: list[str] | None = None,
    timeout: float = 8.0,
    interval: float = 0.4,
    port: int = LAN_SEARCH_PORT,
) -> list[LanSearchInfo]:
    """Broadcast a LAN search and collect camera replies.

    Retries for up to ``timeout`` seconds because a power-saving camera needs a
    few seconds of Wi-Fi radio warmup before its P4P responder answers (see
    docs/protocol-notes.md). Binds the local socket to ``port`` so replies land
    whether the device answers our source port or the fixed port.
    """
    request = build_lansearch_request(uid)
    targets = targets or ["255.255.255.255"]
    found: dict[str, LanSearchInfo] = {}

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            s.bind(("", port))
        except OSError:
            pass
        s.settimeout(interval)

        import time  # local import: module-level time is banned in some harnesses

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not found:
            for tgt in targets:
                try:
                    s.sendto(request, (tgt, port))
                except OSError:
                    pass
            try:
                while True:
                    data, addr = s.recvfrom(4096)
                    if data == request:
                        continue  # our own broadcast echoed back
                    try:
                        info = parse_lansearch_reply(_deobfuscate(data), src=addr)
                    except ValueError:
                        continue  # not a LAN-search reply
                    found[addr[0]] = info
            except socket.timeout:
                pass
    return list(found.values())
