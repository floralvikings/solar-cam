"""High-level LAN video client: camera -> Annex-B H.264 frames, no cloud.

Ties the layers together (discover -> lanstreamreq/auth -> 0x1308 -> KCP receive
+ ACK -> reassemble -> strip AV header -> H.264). Pure Python, so it can run in a
Home Assistant add-on / HACS integration. Audio (message type 0x13) is skipped
for now; video is type 0x11 carrying Annex-B H.264.
"""

from __future__ import annotations

import os
import socket
import struct
import time
from collections.abc import Iterator

from .crypto import decode
from .lansearch import discover
from .packet import MAGIC, build, parse_plain
from .kcp import KcpReceiver
from .session import (
    build_alive,
    build_lanstreamreq,
    parse_lanstreamrsp,
)

VIDEO_TYPE = 0x11
AUDIO_TYPE = 0x13
LAN_SEARCH_PORT = 32762


def _has_sps(frame: bytes) -> bool:
    i = frame.find(b"\x00\x00\x00\x01")
    while i >= 0:
        if (frame[i + 4] & 0x1F) == 7:  # SPS
            return True
        i = frame.find(b"\x00\x00\x00\x01", i + 4)
    return False


def extract_h264(message: bytes) -> bytes | None:
    """Return the Annex-B H.264 from a video message, or None (audio/other).

    Video messages (type 0x11) are a small AV header followed by Annex-B H.264;
    the payload begins at the first 00 00 00 01 start code (~offset 32).
    """
    if len(message) < 5 or message[0] != VIDEO_TYPE:
        return None
    k = message.find(b"\x00\x00\x00\x01")
    if k < 0 or k > 48:
        return None
    return message[k:]


def stream_h264(
    uid: str,
    camera_ip: str,
    client_ip: str,
    *,
    password: bytes | None = None,
    broadcast: str = "255.255.255.255",
    conv: int | None = None,
    port: int = LAN_SEARCH_PORT,
    warmup_timeout: float = 15.0,
    key_start: bool = True,
    frame_timeout: float = 20.0,
) -> Iterator[bytes]:
    """Yield Annex-B H.264 frames from the camera over the LAN.

    ``password`` defaults to the credential the camera returns in its
    LanSearchInfo. ``client_ip`` is our LAN IP (where the camera streams video).
    With ``key_start`` (default) the first yielded frame is a keyframe (SPS), so
    a downstream decoder/muxer (ffmpeg, go2rtc) syncs cleanly. Runs until the
    generator is closed or the socket errors.
    """
    infos = discover(uid, targets=[broadcast, camera_ip], timeout=warmup_timeout)
    if not infos:
        raise RuntimeError(f"camera {uid} not found on the LAN")
    if password is None:
        password = (infos[0].credential or "").encode("ascii")
    if conv is None:
        conv = int.from_bytes(os.urandom(4), "little")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", 0))
    my_port = s.getsockname()[1]
    s.settimeout(0.25)

    lsr = build_lanstreamreq(
        uid, conv=conv, password=password, client_ip=client_ip, client_port=my_port
    )
    rsp = None
    for _ in range(6):
        s.sendto(lsr, (camera_ip, port))
        time.sleep(0.1)
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline and rsp is None:
        try:
            data, _ = s.recvfrom(65535)
        except socket.timeout:
            break
        if data == lsr:
            continue
        try:
            dec = decode(data)
            if dec[:4] == MAGIC and struct.unpack_from("<H", dec, 8)[0] == 0x1308:
                rsp = parse_lanstreamrsp(dec)
        except Exception:
            pass
    if rsp is None:
        s.close()
        raise RuntimeError("no 0x1308 (auth failed? camera busy? password wrong?)")

    sess_port = rsp.session_port
    kcp = KcpReceiver(conv)
    last_alive = 0.0
    synced = not key_start
    last_data = time.monotonic()
    try:
        # kick the stream
        for _ in range(3):
            s.sendto(build_alive(conv), (camera_ip, sess_port))
        while True:
            now = time.monotonic()
            # Watchdog: if the camera stops feeding video (it slept, or another
            # client took over the single session), stop instead of looping
            # forever holding the session. Bounds any stuck/orphaned client.
            if now - last_data > frame_timeout:
                return
            if now - last_alive > 1.0:
                s.sendto(build_alive(conv), (camera_ip, sess_port))
                last_alive = now
            try:
                data, _ = s.recvfrom(65535)
            except socket.timeout:
                continue
            if data == lsr:
                continue
            try:
                dec = decode(data)
            except Exception:
                continue
            if dec[:4] != MAGIC:
                continue
            pkt = parse_plain(dec)
            if pkt.msgtype != 0x140A:
                continue
            last_data = now
            kcp.input(pkt.body)
            for msg in kcp.messages():
                frame = extract_h264(msg)
                if not frame:
                    continue
                if not synced:
                    if not _has_sps(frame):
                        continue  # wait for the first keyframe (SPS)
                    synced = True
                yield frame
            # ACK what we received so the camera keeps sending
            acks = kcp.ack_segments()
            for i in range(0, len(acks), 8):  # pack a few ACK segs per 0x1409
                s.sendto(build(0x1409, b"".join(acks[i : i + 8]), aux=0x21),
                         (camera_ip, sess_port))
    finally:
        s.close()
