"""Direct LAN session establishment (preconnect/PUNCH2LAN + KCP).

WORK IN PROGRESS. The state machine and the fields are known from the SDK trace
(docs/session-flow.md); the exact preconnect/lanstreamreq byte layouts and the
KCP conv derivation are *candidates* to be pinned empirically by driving this
against the real camera while capturing our own Mac<->camera traffic.

Reverse-engineered flow (client peer side):
    mgmt_init -> make random_id -> LAN-search -> preconnect/PUNCH2LAN
       -> KCP channel(s) keyed by random_id -> lanstreamreq -> H.264 over KCP

Transport is stock KCP (github.com/skywind3000/kcp); we will wrap an existing
KCP implementation rather than reimplement the reliability layer.
"""

from __future__ import annotations

import ipaddress
import socket
import struct
from dataclasses import dataclass

from .crypto import decode as _deobfuscate
from .lansearch import LanSearchInfo
from .packet import MAGIC, MsgType, build, parse_plain

# --- LAN stream request/response (VERIFIED against the live camera) ---------
# send_lanstreamreq builds msgtype 0x1307, aux 0x21, 108-byte body; the camera
# replies 0x1308 from a freshly-opened session port with its endpoint + a
# session id, retransmitting until the client connects (KCP) to that port.
LAN_STREAM_REQ_LEN = 108


def build_lanstreamreq(
    uid: str,
    *,
    conv: int = 0,
    password: bytes = b"",
    password_offset: int = 76,
    stream_index: int = 0,
) -> bytes:
    """Build the obfuscated LAN stream-start request (msgtype 0x1307).

    The camera runs ``p4p_device_auth`` on this request and **frees the session
    (no video) unless the 16-byte view password authenticates** (verified by
    disassembly: on auth != 0 the device calls ``p4p_device_free_session``).

    Fields (from the SDK's ``send_lanstreamreq``):
      * body[0]      = 0x01
      * body[24:44]  = device UID (checked against the device's own UID)
      * body[72:76]  = ``conv`` (client randomID; also the KCP conv)
      * body[76:92]  = 16-byte **view password** (``sess+0xf8``) -- the auth gate

    The password is NOT the LanSearchInfo credential and is not a common
    default (both tried, both rejected); it is the value set when the camera
    was bound in UBox. ``password_offset`` is exposed because the exact slot
    is our best inference (body[76]) pending a ground-truth dump.
    """
    uid = uid.strip().upper()
    body = bytearray(LAN_STREAM_REQ_LEN)
    body[0] = 0x01
    body[24:44] = uid.encode("ascii")
    struct.pack_into("<I", body, 72, conv & 0xFFFFFFFF)
    if password:
        body[password_offset:password_offset + len(password[:16])] = password[:16]
    struct.pack_into("<I", body, 100, stream_index)
    return build(MsgType.LAN_STREAM_REQ, bytes(body), aux=0x21)


# --- Session keepalive + KCP (VERIFIED against the real decrypted session) ---
# Upstream (client->camera): 0x1405 alive (aux 0x21) + 0x1409 KCP ACKs (aux 0x21).
# Downstream (camera->client): 0x140a KCP PUSH video (aux 0x18) + 0x1406 keepalive.
# The 32-bit conv is client-chosen (randomID); it appears in lanstreamreq
# body[72], in the alive body[8:12], and as the first field of every KCP segment.
ALIVE_AUX = 0x21
KCP_AUX = 0x21
VIDEO_AUX = 0x18
IKCP_CMD_PUSH = 81
IKCP_CMD_ACK = 82
IKCP_CMD_WASK = 83
IKCP_CMD_WINS = 84


def build_alive(conv: int, *, channels: int = 0x0007) -> bytes:
    """0x1405 session-alive. Body = u16 channels + pad + conv(u32 LE) + pad(8).

    Verified real-session body: ``00 07 00 00 00 00 00 00 <conv LE> 00*8``.
    ``channels`` (0x0007) selects the requested stream channels.
    """
    body = struct.pack("<H", channels) + b"\x00" * 6 + struct.pack("<I", conv) + b"\x00" * 8
    return build(0x1405, body, aux=ALIVE_AUX)


def build_kcp_segment(conv: int, cmd: int, *, frg: int = 0, wnd: int = 512,
                      ts: int = 0, sn: int = 0, una: int = 0, payload: bytes = b"") -> bytes:
    """Stock ikcp 24-byte header + payload (little-endian)."""
    return struct.pack("<IBBHIIII", conv, cmd, frg, wnd, ts, sn, una, len(payload)) + payload


def build_kcp_ack(conv: int, sn: int, una: int, **kw) -> bytes:
    """0x1409 upstream message wrapping a KCP ACK segment."""
    return build(0x1409, build_kcp_segment(conv, IKCP_CMD_ACK, sn=sn, una=una, **kw), aux=KCP_AUX)


def parse_kcp_segment(body: bytes):
    """Parse the KCP header from a 0x140a/0x1409 body. Returns a dict or None."""
    if len(body) < 24:
        return None
    conv, cmd, frg, wnd, ts, sn, una, ln = struct.unpack_from("<IBBHIIII", body, 0)
    return {"conv": conv, "cmd": cmd, "frg": frg, "wnd": wnd, "ts": ts,
            "sn": sn, "una": una, "len": ln, "payload": body[24:24 + ln]}


@dataclass
class LanStreamResponse:
    """Parsed 0x1308 stream response: the camera's session endpoint."""

    camera_ip: str
    session_port: int
    session_id: int          # body[24:28]; candidate KCP conv
    uid: str
    raw_body: bytes = b""


def parse_lanstreamrsp(decoded: bytes) -> LanStreamResponse:
    """Parse a deobfuscated 0x1308 response."""
    pkt = parse_plain(decoded)
    if pkt.msgtype != 0x1308:
        raise ValueError(f"not a lanstream response (0x{pkt.msgtype:04x})")
    b = pkt.body
    camera_ip = socket.inet_ntoa(b[12:16])
    session_port = int.from_bytes(b[16:18], "big")   # network order
    session_id = int.from_bytes(b[24:28], "little")
    uid = b[28:48].split(b"\x00", 1)[0].decode("ascii", "replace")
    return LanStreamResponse(camera_ip, session_port, session_id, uid, b)


def make_random_id(seed_bytes: bytes) -> int:
    """32-bit session correlation id (SDK: p4p_client_randomID; also the KCP conv).

    The SDK derives it from a randomness source; for interop the exact PRNG does
    not matter as long as both peers use the value we send in the preconnect.
    Callers pass entropy explicitly (``os.urandom(4)``) so this stays testable
    and side-effect free.
    """
    return int.from_bytes(seed_bytes[:4].ljust(4, b"\x00"), "little") & 0xFFFFFFFF


def _addr_to_u32(ip: str) -> int:
    return int(ipaddress.IPv4Address(ip))


@dataclass
class ConnectParams:
    camera_ip: str
    info: LanSearchInfo
    client_lan_ip: str
    client_pub_ip: str | None = None
    port: int = 32762


def build_preconnect(random_id: int, params: ConnectParams) -> bytes:
    """CANDIDATE preconnect/PUNCH2LAN packet (msgtype ~0x110A).

    The device-side handler logs
    ``add deviceSID, randomID, clientLanAddr, clientPubAddr`` — so the body
    carries at least: random_id, client LAN addr, client public addr. Exact
    field order/size is unconfirmed; this is a first draft to send-and-observe.
    Do not treat the produced bytes as final.
    """
    lan = _addr_to_u32(params.client_lan_ip)
    pub = _addr_to_u32(params.client_pub_ip or params.client_lan_ip)
    body = struct.pack("<III", random_id, lan, pub)
    return build(MsgType.PRECONNECT, body)


class P4PSession:
    """Skeleton client session. Real connect()/start_video() land in Phase 2b."""

    def __init__(self, params: ConnectParams):
        self.params = params
        self.random_id: int | None = None
        self.device_sid: int | None = None
        self.client_sid: int | None = None

    def connect(self) -> None:  # pragma: no cover - WIP
        raise NotImplementedError(
            "preconnect/KCP handshake not implemented yet; see docs/session-flow.md"
        )

    def start_video(self):  # pragma: no cover - WIP
        raise NotImplementedError("lanstreamreq/KCP AV not implemented yet")
