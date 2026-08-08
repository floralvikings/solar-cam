"""Shared config + P4P message builders for the interop probes.

Loads the device identity from an UNTRACKED source so no secrets ever live in git:
  1. environment variables, else
  2. local/device.json   (gitignored)

Required : RBX_UID / "uid", RBX_VIEW_PW / "view_password", RBX_CAMERA_IP / "camera_ip"
Optional : RBX_CLIENT_IP / "client_ip"  (this host's LAN IP; where video is streamed)
           RBX_BROADCAST / "broadcast"  (LAN broadcast for discovery)

local/device.json example (create it; it is gitignored):
  {
    "uid": "XXXXXXXXXXXXXXXXXXXX",
    "view_password": "................",
    "camera_ip": "192.168.x.x",
    "client_ip": "192.168.x.x",
    "broadcast": "192.168.x.255"
  }

Importing this module also puts the repo root on sys.path so `import p4p...` works.
The handshake templates (knock/confirm/stream/alive) are BUILT from the UID + view
password here, so those secrets never need to be pasted into a probe again.
"""
from __future__ import annotations
import os, sys, json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

_CONFIG_JSON = REPO / "local" / "device.json"


def _load() -> dict:
    cfg: dict = {}
    if _CONFIG_JSON.exists():
        cfg = json.loads(_CONFIG_JSON.read_text())

    def get(env: str, key: str, *, required: bool = True, default=None):
        val = os.environ.get(env) or cfg.get(key) or default
        if required and not val:
            raise SystemExit(
                f"Missing {env} / \"{key}\".\n"
                f"Set env {env}, or create {_CONFIG_JSON} (gitignored) with:\n"
                '  {"uid": "...", "view_password": "...", "camera_ip": "192.168.x.x",\n'
                '   "client_ip": "192.168.x.x", "broadcast": "192.168.x.255"}')
        return val

    return {
        "uid":       get("RBX_UID", "uid"),
        "view_pw":   get("RBX_VIEW_PW", "view_password"),
        "camera_ip": get("RBX_CAMERA_IP", "camera_ip"),
        "client_ip": get("RBX_CLIENT_IP", "client_ip", required=False, default="0.0.0.0"),
        "broadcast": get("RBX_BROADCAST", "broadcast", required=False, default="255.255.255.255"),
    }


_CFG = _load()
UID: str       = _CFG["uid"].strip().upper()
VIEW_PW: str   = _CFG["view_pw"]
CAMERA_IP: str = _CFG["camera_ip"]
CLIENT_IP: str = _CFG["client_ip"]
BROADCAST: str = _CFG["broadcast"]


def _uid_bytes() -> bytes:
    return UID.encode("ascii").ljust(20, b"\x00")[:20]

def _pw_field() -> bytes:            # 16-byte view-password field as it sits in the knock body
    return VIEW_PW.encode().ljust(16, b"\x00")[:16]


# 16-byte P4P headers (magic|len|flags|msgtype|aux|[0xc:0xe]|[0xe]|[0xf]).
_HDR_130B = bytes.fromhex("07181000440000000b13210000000004")   # knock
_HDR_130D = bytes.fromhex("07181000240000000d13210000000004")   # knock confirm
_HDR_1309 = bytes.fromhex("07181000540000000913210000000000")   # channel/stream open
_HDR_1405 = bytes.fromhex("0718100014000b0005142100e4810000")   # alive


def build_knock(rid: bytes, conv_le: bytes, hdr0f: int = 0x00, chanidx: int = 0x01) -> bytes:
    """0x130b knock: UID(20) + view-pw(16) + marker + randomID(4)+conv(4) + "admin".

    Device-side check in p4p_device_handle_knock @0x44458 (libUBICAPIs.so):
      chanidx = pkt[0x3b] (the marker's last byte, `chanidx` here) selects the
        client-session slot  gp + 0x101c + chanidx*308.
      slot[0]   != 0        -> slot must be pre-allocated (lanstreamreq does this)
      slot[0xc] == pkt[0x40] -> conv; lanstreamreq set slot[0xc] = its body[72] conv
      slot[0x17]== pkt[0xf]  -> hdr0f; lanstreamreq set slot[0x17] = its body[3]
    So chanidx MUST be the device-assigned index returned in the 0x1308 response;
    hdr0f MUST equal the lanstreamreq body[3] (0 in our build_lanstreamreq)."""
    body = (_uid_bytes() + _pw_field()
            + bytes([0, 0, 0, 0, 0, 0, 0x0b, chanidx & 0xff]) + rid[:4] + conv_le[:4]
            + b"admin" + bytes(11))
    hdr = bytearray(_HDR_130B); hdr[15] = hdr0f & 0xff
    return bytes(hdr) + body

def build_confirm(rid: bytes, conv_le: bytes, hdr0f: int = 0x00, chanidx: int = 0x01) -> bytes:
    """0x130d knock-ack, completing the 2-step handshake.

    p4p_device_handle_knock_ack @0x44e1c: chanidx = pkt[0x2b]; slot =
    gp+0x101c+chanidx*308; requires slot[0]!=0 AND slot[0x17]==pkt[0xf], then sets
    slot[0x19]=0 (knock set it to 1 = pending; confirm clears it = established).
    So chanidx must be the device-assigned index and hdr0f must match the
    lanstreamreq body[3] (0), same as the knock."""
    hdr = bytearray(_HDR_130D); hdr[15] = hdr0f & 0xff
    body = bytearray(26) + bytes([0x0b, chanidx & 0xff]) + rid[:4] + conv_le[:4]
    return bytes(hdr) + bytes(body)

def build_stream(rid: bytes, conv_le: bytes) -> bytes:
    """0x1309 channel-open; randomID+conv near the tail."""
    return _HDR_1309 + bytes([0x01, 0x04]) + bytes(56) + b"\x0b\x01" + rid[:4] + conv_le[:4] + bytes(16)

def build_alive_msg(rid: bytes, conv_le: bytes) -> bytes:
    """0x1405 alive; header[0xc:0xe] mirrors randomID[2:4] as the real app does."""
    hdr = bytearray(_HDR_1405); hdr[12:14] = rid[2:4]
    return bytes(hdr) + bytes([0x00, 0x0b, 0x01, 0x00]) + rid[:4] + conv_le[:4] + bytes(8)
