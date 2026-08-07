"""Relay-path P4P session (msgtype 0x1105) — the one that gets FULL ioctrl.

Why this exists
---------------
The camera creates a session either way, but ``p4p_device_receiver`` routes the
two stream requests to different handlers, and each reports a different status
to the vendor app via ``p4p_device_status_callback``:

    0x1307 lanstreamreq -> p4p_device_handle_lanstreamreq -> status = 3
    0x1105 rlystreamreq -> p4p_device_handle_rlystreamreq -> status = 1

``ubia_t23`` whitelists ioctrl commands on that status, so a status-3 session
gets media plus a small command subset and silently drops every query, while a
status-1 (relay) session gets the full command set and *answers*. Nothing
cryptographic distinguishes them — only how the session was opened.

Both paths then use the identical knock (0x130b) / confirm (0x130d) handshake
and carry ioctrl as type-3 frames over KCP inside 0x1409.

This module is research tooling. It is NOT imported by the HA integration; the
integration still opens a LAN session in ``p4p/client.py``. Porting this
handshake there is tracked as the next step. No secrets live here — identity
comes from :mod:`p4p_probe_config` (env or the gitignored ``local/device.json``).
"""

from __future__ import annotations

import os
import socket
import struct
import time
from dataclasses import dataclass, field

import p4p_probe_config as cfg
from p4p.crypto import decode, encode
from p4p.kcp import KcpReceiver, KcpSender, build_ioctrl_frame
from p4p.lansearch import LAN_SEARCH_PORT, discover
from p4p.packet import MAGIC, build
from p4p.session import build_alive

_KCP_HDR = struct.Struct("<IBBHIIII")
_IKCP_CMD_PUSH = 81

# Frame leads seen on the AV channel that are media, not ioctrl replies.
_MEDIA_LEADS = (0x11, 0x13)
RLY_STREAM_REQ = 0x1105
RLY_STREAM_RSP = 0x1106


@dataclass
class IoctrlResponse:
    """One decoded type-3 ioctrl frame from the camera."""

    iotype: int
    data: bytes
    lead: int = 3

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"IoctrlResponse(iotype={self.iotype}, {len(self.data)}B, {self.data[:32].hex()})"


def _msgtype(decoded: bytes) -> int:
    return struct.unpack_from("<H", decoded, 8)[0]


def _body(decoded: bytes) -> bytes:
    return decoded[16:16 + struct.unpack_from("<H", decoded, 4)[0]]


def _ip4(addr: str) -> bytes:
    return socket.inet_aton(addr)


def build_rlystreamreq(uid: str, *, client_ip: str, client_port: int, camera_port: int,
                       credential: bytes, random_id: bytes, conv: int,
                       index: int = 0, counter: int = 0) -> bytes:
    """0x1105 relay stream request (108-byte body, aux 0x41).

    Layout recovered from captured app traffic; every field verified to be
    required by ``p4p_device_handle_rlystreamreq``::

        +0x00  01 00 00 <counter>
        +0x04  u16 BE   our UDP port
        +0x06  u16 BE   the camera port we send to (32762)
        +0x08  our IP           (the "peer" address)
        +0x0c  c0 00 00 08      constant in every captured sample
        +0x10  d4 0b 00 00      unknown; copied verbatim
        +0x14  our IP           (the app puts the camera's public WAN IP here)
        +0x18  UID (20)
        +0x2c  credential (16)  = the view password from LAN-search
        +0x42  0x0b, index
        +0x44  randomID (4)
        +0x48  conv (4, LE)
        +0x4c  "admin"
    """
    b = bytearray(0x6C)
    b[0] = 1
    b[3] = counter & 0xFF
    struct.pack_into(">H", b, 4, client_port & 0xFFFF)
    struct.pack_into(">H", b, 6, camera_port & 0xFFFF)
    b[8:12] = _ip4(client_ip)
    b[12:16] = bytes.fromhex("c0000008")
    b[16:20] = bytes.fromhex("d40b0000")
    b[20:24] = _ip4(client_ip)
    b[24:44] = uid.strip().upper().encode("ascii").ljust(20, b"\x00")[:20]
    b[44:60] = credential.ljust(16, b"\x00")[:16]
    b[66] = 0x0B
    b[67] = index & 0xFF
    b[68:72] = random_id[:4]
    struct.pack_into("<I", b, 72, conv & 0xFFFFFFFF)
    b[76:81] = b"admin"
    return build(RLY_STREAM_REQ, bytes(b), aux=0x41)


@dataclass
class RelaySession:
    """An open, knocked-through relay session ready for ioctrl."""

    sock: socket.socket
    camera_ip: str
    session_port: int
    conv: int
    index: int
    rcv: KcpReceiver
    snd: KcpSender
    knock_status: str | None = None
    responses: list[IoctrlResponse] = field(default_factory=list)

    @property
    def conv_le(self) -> bytes:
        return struct.pack("<I", self.conv)

    def _send(self, msgtype: int, payload: bytes, *, aux: int = 0x21) -> None:
        self.sock.sendto(build(msgtype, payload, aux=aux), (self.camera_ip, self.session_port))

    def send_ioctrl(self, iotype: int, data: bytes, *, avchannel: int = 0) -> None:
        """Push one ioctrl command onto the session's reliable KCP channel."""
        ts = int(time.monotonic() * 1000) & 0xFFFFFFFF
        seg = self.snd.push(build_ioctrl_frame(avchannel, iotype, data),
                            una=self.rcv.rcv_nxt, ts=ts)
        self._send(0x1409, seg)

    def pump(self, seconds: float) -> list[IoctrlResponse]:
        """Service the session for ``seconds``: keepalive, retransmit, ACK, collect.

        Returns only the ioctrl frames decoded during *this* call; every frame is
        also appended to :attr:`responses`.

        Segments are walked directly out of each 0x1409/0x140a body rather than
        taken from ``rcv.messages()``: a reply whose first segment we missed
        would otherwise stall reassembly forever and hide the answer. ``rcv`` is
        still fed so the camera keeps getting ACKs and its window advances.
        """
        got: list[IoctrlResponse] = []
        end = time.monotonic() + seconds
        last_alive = last_retx = 0.0
        while time.monotonic() < end:
            now = time.monotonic()
            if now - last_alive > 0.6:
                self.sock.sendto(build_alive(self.conv), (self.camera_ip, self.session_port))
                last_alive = now
            if now - last_retx > 0.15:
                for seg in self.snd.retransmit_segments():
                    self._send(0x1409, seg)
                last_retx = now
            try:
                wire, _ = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            try:
                dd = decode(wire)
            except Exception:
                continue
            if dd[:4] != MAGIC or _msgtype(dd) not in (0x1409, 0x140A):
                continue
            body = _body(dd)
            self.snd.note_acks(body)
            got.extend(self._decode_ioctrl(body))
            self.rcv.input(body)
            acks = self.rcv.ack_segments()
            for i in range(0, len(acks), 8):
                self._send(0x1409, b"".join(acks[i:i + 8]))
        self.responses.extend(got)
        return got

    def _decode_ioctrl(self, body: bytes) -> list[IoctrlResponse]:
        out: list[IoctrlResponse] = []
        off = 0
        while len(body) - off >= _KCP_HDR.size:
            conv, cmd, _frg, _wnd, _ts, _sn, _una, ln = _KCP_HDR.unpack_from(body, off)
            if conv != self.conv:
                break
            payload = body[off + _KCP_HDR.size:off + _KCP_HDR.size + ln]
            off += _KCP_HDR.size + ln
            if cmd != _IKCP_CMD_PUSH or len(payload) < 0x10:
                continue
            lead = struct.unpack_from("<I", payload, 0)[0]
            if lead in _MEDIA_LEADS:
                continue
            datalen = struct.unpack_from("<I", payload, 8)[0]
            iotype = struct.unpack_from("<I", payload, 0xC)[0]
            if datalen > 0x10000:
                continue
            out.append(IoctrlResponse(iotype, payload[0x10:0x10 + datalen], lead))
        return out

    def close(self) -> None:
        self.sock.close()


def open_relay_session(*, uid: str | None = None, camera_ip: str | None = None,
                       client_ip: str | None = None, broadcast: str | None = None,
                       view_pw: str | None = None, discover_timeout: float = 15.0,
                       settle: float = 2.5, verbose: bool = True) -> RelaySession:
    """LAN-search, open a 0x1105 relay session, knock through it, return it ready.

    Raises ``RuntimeError`` if the camera is not found or never answers 0x1106.
    """
    uid = (uid or cfg.UID).strip().upper()
    camera_ip = camera_ip or cfg.CAMERA_IP
    client_ip = client_ip or cfg.CLIENT_IP
    broadcast = broadcast or cfg.BROADCAST

    infos = discover(uid, targets=[broadcast, camera_ip], timeout=discover_timeout)
    if not infos:
        raise RuntimeError("camera did not answer LAN-search (asleep? wrong IP?)")
    credential = (infos[0].credential or view_pw or cfg.VIEW_PW).encode()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", 0))
    sock.settimeout(0.15)

    random_id = os.urandom(4)
    conv = int.from_bytes(os.urandom(4), "little")
    req = build_rlystreamreq(uid, client_ip=client_ip, client_port=sock.getsockname()[1],
                             camera_port=LAN_SEARCH_PORT, credential=credential,
                             random_id=random_id, conv=conv)

    session_port: int | None = None
    index = 0
    saw_rsp = False
    for _ in range(6):
        sock.sendto(req, (camera_ip, LAN_SEARCH_PORT))
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            try:
                wire, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            if wire == req:
                continue
            try:
                dd = decode(wire)
            except Exception:
                continue
            if dd[:4] != MAGIC:
                continue
            mt = _msgtype(dd)
            if mt == RLY_STREAM_RSP:
                session_port = addr[1]
                saw_rsp = True
                body = _body(dd)
                index = body[0x35] if len(body) > 0x35 else 0
            elif session_port is None and mt == 0x1406:
                # keepalive from the new session port; usable if 0x1106 was lost
                session_port = addr[1]
        if session_port:
            break
    if not session_port:
        sock.close()
        raise RuntimeError("no 0x1106 — the camera refused to create a relay session")

    session = RelaySession(sock=sock, camera_ip=camera_ip, session_port=session_port,
                           conv=conv, index=index, rcv=KcpReceiver(conv), snd=KcpSender(conv))
    if verbose:
        print(f"relay session up: port={session_port} index={index} conv=0x{conv:08x}"
              f"{'' if saw_rsp else '  [WARNING: no 0x1106 seen — index is a guess]'}")
    session.pump(settle)

    # knock 0x130b -> 0x130c (status 0000 = accepted) -> confirm 0x130d
    for _ in range(4):
        sock.sendto(encode(cfg.build_knock(random_id, session.conv_le, 0x00, index)),
                    (camera_ip, session_port))
        time.sleep(0.1)
    deadline = time.monotonic() + 1.5
    while time.monotonic() < deadline:
        try:
            wire, _ = sock.recvfrom(65535)
        except socket.timeout:
            continue
        try:
            dd = decode(wire)
        except Exception:
            continue
        if dd[:4] == MAGIC and _msgtype(dd) == 0x130C and len(dd) >= 38:
            session.knock_status = dd[36:38].hex()
    for _ in range(4):
        sock.sendto(encode(cfg.build_confirm(random_id, session.conv_le, 0x00, index)),
                    (camera_ip, session_port))
        time.sleep(0.08)
    if verbose:
        print(f"knock status: {session.knock_status}"
              f"{'  (accepted)' if session.knock_status == '0000' else ''}")
    return session
