#!/usr/bin/env python3
"""Upgrade a WORKING lanstreamreq session to an ioctrl session via the knock (0x130b).

Why this should work (device-side p4p_device_handle_knock @0x44458 in libUBICAPIs.so):
auth (p4p_device_auth @0x41bb4) is a plaintext memcmp of UID + view-password + "admin",
all of which we hold, and our knock already PASSES it. The camera's 0x130c status=0xffff
is a POST-auth channel-slot rejection needing, after auth:
    chanstruct[0]   != 0            (slot allocated by a prior msg)
    chanstruct[0xc] == pkt+0x40     (pkt+0x40 = the conv)
    chanstruct[0x17] == knock header[0xf]
lanstreamreq allocates a channel bound to our conv (that's how we get video), so re-using
that conv in the knock should satisfy chanstruct[0xc]==conv. We sweep header[0xf] to hit
chanstruct[0x17]. SUCCESS SIGNAL: 0x1402 acks > 0 = ioctrl accepted (controls + FILE_DOWNLOAD).

Config (UID / view-pw / IPs) comes from env or local/device.json via p4p_probe_config.
Run with the camera FREE (disable the HA integration). Read-only: UDP only.
"""
import os, sys, time, struct, socket
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p4p_probe_config as cfg   # also puts repo root on sys.path
from p4p.lansearch import discover, LAN_SEARCH_PORT
from p4p.session import build_lanstreamreq, parse_lanstreamrsp, build_alive
from p4p.packet import MAGIC, build
from p4p.crypto import decode, encode
from p4p.kcp import KcpReceiver
from p4p.client import extract_h264

CAM, ME, BC, UID = cfg.CAMERA_IP, cfg.CLIENT_IP, cfg.BROADCAST, cfg.UID

def mt(d): return struct.unpack_from("<H", d, 8)[0]
def status_of(dd): return dd[36:38].hex() if len(dd) >= 38 else "??"

def build_ioctrl(iotype, data12, idx, seq, aux=0x21):
    body = bytearray(24); body[0] = 3
    struct.pack_into("<H", body, 4, seq & 0xffff); struct.pack_into("<H", body, 6, 12)
    struct.pack_into("<I", body, 8, iotype); body[12:24] = data12
    hdr = MAGIC + struct.pack("<HHHH", len(body), 0, 0x1401, aux) + struct.pack("<HBB", idx & 0xffff, 0, 0)
    return encode(hdr + bytes(body))

def main():
    infos = discover(UID, targets=[BC, CAM], timeout=15.0)
    if not infos: raise SystemExit("camera not found (free it: disable HA integration)")
    pw = (infos[0].credential or cfg.VIEW_PW).encode()
    conv = int.from_bytes(os.urandom(4), "little"); conv_le = conv.to_bytes(4, "little")
    print(f"conv=0x{conv:08x}")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("", 0)); s.settimeout(0.3)
    myport = s.getsockname()[1]

    # 1) lanstreamreq -> session port (working video session bound to conv)
    lsr = build_lanstreamreq(UID, conv=conv, password=pw, client_ip=ME, client_port=myport)
    sport = None
    for _ in range(6): s.sendto(lsr, (CAM, LAN_SEARCH_PORT)); time.sleep(0.1)
    t = time.monotonic() + 3
    while time.monotonic() < t and sport is None:
        try: d, _ = s.recvfrom(65535)
        except socket.timeout: break
        if d == lsr: continue
        try:
            dd = decode(d)
            if dd[:4] == MAGIC and mt(dd) == 0x1308:
                sport = parse_lanstreamrsp(dd).session_port
        except Exception: pass
    if not sport: raise SystemExit("no 0x1308 lanstreamrsp (busy/auth)")
    print(f"session port = {sport}")

    # 2) start video, grab session index
    kcp = KcpReceiver(conv); idx = None
    for _ in range(3): s.sendto(build_alive(conv), (CAM, sport))
    t = time.monotonic() + 3; last = 0
    while time.monotonic() < t:
        now = time.monotonic()
        if now - last > 0.7: s.sendto(build_alive(conv), (CAM, sport)); last = now
        try: d, _ = s.recvfrom(65535)
        except socket.timeout: continue
        try: dd = decode(d)
        except Exception: continue
        if dd[:4] != MAGIC or mt(dd) != 0x140A: continue
        if idx is None: idx = struct.unpack_from("<H", dd, 0xc)[0]; print(f"video up, session index={idx}")
        kcp.input(dd[16:16+struct.unpack_from('<H', dd, 4)[0]])
        for m in kcp.messages(): extract_h264(m)
        ak = kcp.ack_segments()
        for i in range(0, len(ak), 8): s.sendto(build(0x1409, b"".join(ak[i:i+8]), aux=0x21), (CAM, sport))
    if idx is None: print("  (no video yet; continuing to knock anyway)")

    # 3) knock into that session, sweeping header[0xf] to match chanstruct[0x17]
    passed_hdr = None
    for hdr0f in (0x04, 0x00, 0x01, 0x10, 0x11):
        got = None
        for _ in range(4): s.sendto(encode(cfg.build_knock(os.urandom(4), conv_le, hdr0f)), (CAM, sport)); time.sleep(0.1)
        t = time.monotonic() + 1.2
        while time.monotonic() < t:
            try: d, _ = s.recvfrom(65535)
            except socket.timeout: continue
            try: dd = decode(d)
            except Exception: continue
            if dd[:4] == MAGIC and mt(dd) == 0x130c: got = status_of(dd)
        print(f"  knock hdr[0xf]=0x{hdr0f:02x} -> 0x130c status={got}")
        if got and got != "ffff":
            passed_hdr = hdr0f; print(f"  >>> STATUS FLIPPED with hdr[0xf]=0x{hdr0f:02x}"); break
    if passed_hdr is None:
        print(">>> knock still ffff on all header values; channel-match not satisfied by lanstreamreq")

    # 4) test ioctrl: PTZ(4097) + FILE_LIST(4864); count acks
    acks = frsp = 0
    if idx is not None:
        ptz = bytearray(12); ptz[5] = 3; ptz[6] = 8
        seq = 0; last_a = last_p = 0; t = time.monotonic() + 5
        while time.monotonic() < t:
            now = time.monotonic()
            if now - last_a > 0.7: s.sendto(build_alive(conv), (CAM, sport)); last_a = now
            if now - last_p > 0.3:
                s.sendto(build_ioctrl(4097, bytes(ptz), idx, seq), (CAM, sport)); seq += 1
                s.sendto(build_ioctrl(4864, bytes(12), idx, seq), (CAM, sport)); seq += 1
                last_p = now
            try: d, _ = s.recvfrom(65535)
            except socket.timeout: continue
            try: dd = decode(d)
            except Exception: continue
            if dd[:4] != MAGIC: continue
            m = mt(dd)
            if m == 0x1402: acks += 1
            if m in (0x4865, 0x1403): frsp += 1
            if m == 0x140A:
                kcp.input(dd[16:16+struct.unpack_from('<H', dd, 4)[0]])
                for mm in kcp.messages(): extract_h264(mm)
                ak = kcp.ack_segments()
                for i in range(0, len(ak), 8): s.sendto(build(0x1409, b"".join(ak[i:i+8]), aux=0x21), (CAM, sport))
    print(f"\nsummary: knock-passed={passed_hdr is not None} 0x1402-acks={acks} file-rsp={frsp}")
    print("acks>0 -> ioctrl accepted = controls + FILE_DOWNLOAD firmware dump unlocked")
    s.close()

main()
