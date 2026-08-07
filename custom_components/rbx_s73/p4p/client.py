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

from .crypto import decode, encode
from .lansearch import discover
from .packet import MAGIC, build, parse_plain
from .kcp import KcpReceiver, KcpSender, build_ioctrl_frame
from .session import (
    build_alive,
    build_knock,
    build_knock_confirm,
    build_lanstreamreq,
    parse_lanstreamrsp,
)

VIDEO_TYPE = 0x11
AUDIO_TYPE = 0x13
LAN_SEARCH_PORT = 32762

# ioctrl (AVIOCTRLDEFs.java); PTZ opcodes from ENUM_PTZCMD.
IOTYPE_PTZ = 4097
PTZ_OPCODE = {"left": 6, "right": 3, "up": 1, "down": 2, "stop": 0}
IOTYPE_NIGHTLIGHT = 46          # UBIA_IO_SET_NIGHTLIGHT (resp 47)


def _light_data(on: bool) -> bytes:
    """SET_NIGHTLIGHT payload — captured from the app: 12 bytes, state at [6].
    ON = ...00 01 00..., OFF = all zero. Camera answers ioType 47 with the
    state echoed plus a success byte."""
    return bytes([0, 0, 0, 0, 0, 0, 1 if on else 0, 0, 0, 0, 0, 0])


def _ptz_data(opcode: int, speed: int = 8) -> bytes:
    """SMsgAVIoctrlPtzCmd — GROUND TRUTH, captured from the phone's own
    command (see docs/protocol-notes.md): 12 bytes, control at [5],
    speed at [6], flag 0x01 at [10]. An earlier 8-byte guess with the
    control at [1] was accepted+acked by the camera but never moved the
    motor, which is what made local PTZ look impossible."""
    return bytes([0, 0, 0, 0, 0, opcode & 0xFF, speed & 0xFF, 0, 0, 0, 1, 0])


def parse_control_command(text: str) -> tuple[int, bytes] | None:
    """Map a text control command to (iotype, data). Returns None if unknown.

    Grammar: ``ptz <left|right|up|down|stop>`` | ``light <on|off>``
    | ``ioctrl <iotype> <hexdata>``.
    """
    parts = text.strip().split()
    if not parts:
        return None
    if parts[0] == "ptz" and len(parts) >= 2 and parts[1] in PTZ_OPCODE:
        return IOTYPE_PTZ, _ptz_data(PTZ_OPCODE[parts[1]])
    if parts[0] == "light" and len(parts) >= 2 and parts[1] in ("on", "off"):
        return IOTYPE_NIGHTLIGHT, _light_data(parts[1] == "on")
    if parts[0] == "ioctrl" and len(parts) >= 3:
        try:
            return int(parts[1]), bytes.fromhex(parts[2])
        except ValueError:
            return None
    return None


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


class LanControlSession:
    """One camera session that streams H.264 AND accepts ioctrl (PTZ/light).

    The camera serves a single AV session, so control must ride the same session
    as the video. ``frames()`` runs the video loop (identical to ``stream_h264``)
    and, once the first keyframe arrives, best-effort completes the 0x130b/0x130d
    handshake to make the session ioctrl-capable. Text commands arrive on an
    optional Unix-datagram control socket (written by the HA process) and are sent
    over the same KCP channel as the real app does. If the handshake or control
    socket is unavailable, video is unaffected — this degrades to video-only.
    """

    def __init__(self, uid: str, camera_ip: str, client_ip: str, *,
                 password: bytes | None = None, broadcast: str = "255.255.255.255",
                 control_sock_path: str | None = None,
                 warmup_timeout: float = 15.0, frame_timeout: float = 20.0) -> None:
        self.uid = uid
        self.camera_ip = camera_ip
        self.client_ip = client_ip
        self.password = password
        self.broadcast = broadcast
        self.control_sock_path = control_sock_path
        self.warmup_timeout = warmup_timeout
        self.frame_timeout = frame_timeout
        self.ioctrl_ready = False

    def _open_control(self):
        if not self.control_sock_path:
            return None
        try:
            if os.path.exists(self.control_sock_path):
                os.unlink(self.control_sock_path)
            cs = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            cs.bind(self.control_sock_path)
            cs.setblocking(False)
            os.chmod(self.control_sock_path, 0o666)
            return cs
        except OSError:
            return None

    def frames(self) -> Iterator[bytes]:
        infos = discover(self.uid, targets=[self.broadcast, self.camera_ip],
                         timeout=self.warmup_timeout)
        if not infos:
            raise RuntimeError(f"camera {self.uid} not found on the LAN")
        pw = self.password if self.password is not None else (infos[0].credential or "").encode("ascii")
        conv = int.from_bytes(os.urandom(4), "little")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", 0))
        my_port = s.getsockname()[1]
        # The control socket is drained once per loop iteration, and this timeout
        # bounds how long an iteration can block. A long timeout adds that much
        # latency to a queued PTZ STOP — which overshoots badly, since the motor
        # keeps running until STOP lands. Keep it short when control is enabled.
        s.settimeout(0.03 if self.control_sock_path else 0.25)

        lsr = build_lanstreamreq(self.uid, conv=conv, password=pw,
                                 client_ip=self.client_ip, client_port=my_port)
        index = None
        sess_port = None
        for _ in range(6):
            s.sendto(lsr, (self.camera_ip, LAN_SEARCH_PORT))
            time.sleep(0.1)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and sess_port is None:
            try:
                data, _ = s.recvfrom(65535)
            except socket.timeout:
                break
            if data == lsr:
                continue
            try:
                dec = decode(data)
                if dec[:4] == MAGIC and struct.unpack_from("<H", dec, 8)[0] == 0x1308:
                    sess_port = parse_lanstreamrsp(dec).session_port
                    # device-assigned session index: marker "04 01 00 00 00 <idx>"
                    # at resp[0x42]; the index byte is resp[0x47]. (It's 0 in the
                    # common case, which hid this off-by-one from resp[0x46].)
                    index = dec[0x47]
            except Exception:
                pass
        if sess_port is None:
            s.close()
            raise RuntimeError("no 0x1308 (auth failed? camera busy? password wrong?)")

        # The control socket is bound only AFTER the handshake completes (below),
        # so the HA side's "socket exists" check means "ioctrl is ready" — commands
        # then fire live instead of queueing (which would batch a nudge to ~0ms).
        cs = None
        kcp = KcpReceiver(conv)
        snd = KcpSender(conv)
        avidx = 0
        last_alive = 0.0
        last_rtx = 0.0
        last_data = time.monotonic()
        synced = False
        handshaked = False
        try:
            for _ in range(3):
                s.sendto(build_alive(conv), (self.camera_ip, sess_port))
            while True:
                now = time.monotonic()
                if now - last_data > self.frame_timeout:
                    return
                if now - last_alive > 1.0:
                    s.sendto(build_alive(conv), (self.camera_ip, sess_port))
                    last_alive = now
                # Retransmit unacked control segments briskly: a lost PTZ packet
                # (especially STOP) means the motor keeps running until it lands,
                # so a 1s retry would overshoot by a lot.
                if now - last_rtx > 0.15 and snd.unacked:
                    for seg in snd.retransmit_segments():
                        s.sendto(build(0x1409, seg, aux=0x21), (self.camera_ip, sess_port))
                    last_rtx = now
                # drain control commands (socket only exists once ioctrl-ready)
                if cs is not None:
                    while True:
                        try:
                            raw = cs.recv(512)
                        except (BlockingIOError, OSError):
                            break
                        cmd = parse_control_command(raw.decode("utf-8", "ignore"))
                        if cmd is not None:
                            self._send_ioctrl(s, snd, kcp, sess_port, avidx, *cmd)
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
                snd.note_acks(pkt.body)
                if avidx == 0:
                    avidx = struct.unpack_from("<H", dec, 0xc)[0]
                kcp.input(pkt.body)
                for msg in kcp.messages():
                    frame = extract_h264(msg)
                    if not frame:
                        continue
                    if not synced:
                        if not _has_sps(frame):
                            continue
                        synced = True
                    yield frame
                # after first keyframe, complete the control handshake once, then
                # expose the control socket (so HA only sends once ioctrl works)
                if synced and not handshaked and index is not None:
                    self._handshake(s, sess_port, conv, pw, index)
                    handshaked = True
                    self.ioctrl_ready = True
                    cs = self._open_control()
                acks = kcp.ack_segments()
                for i in range(0, len(acks), 8):
                    s.sendto(build(0x1409, b"".join(acks[i:i + 8]), aux=0x21),
                             (self.camera_ip, sess_port))
        finally:
            s.close()
            if cs is not None:
                cs.close()
                try:
                    os.unlink(self.control_sock_path)
                except OSError:
                    pass

    def _handshake(self, s, sess_port, conv, pw, index) -> None:
        """Best-effort 0x130b knock + 0x130d confirm to unlock ioctrl."""
        for _ in range(4):
            s.sendto(encode(build_knock(self.uid, pw, os.urandom(4), conv,
                                        chanidx=index, hdr0f=0)),
                     (self.camera_ip, sess_port))
            time.sleep(0.05)
        for _ in range(4):
            s.sendto(encode(build_knock_confirm(os.urandom(4), conv,
                                                chanidx=index, hdr0f=0)),
                     (self.camera_ip, sess_port))
            time.sleep(0.05)

    def _send_ioctrl(self, s, snd, kcp, sess_port, avidx, iotype, data) -> None:
        frame = build_ioctrl_frame(avidx, iotype, data)
        seg = snd.push(frame, una=kcp.rcv_nxt)
        s.sendto(build(0x1409, seg, aux=0x21), (self.camera_ip, sess_port))
