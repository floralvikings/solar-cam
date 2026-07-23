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
import struct
from dataclasses import dataclass

from .lansearch import LanSearchInfo
from .packet import MsgType, build


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
