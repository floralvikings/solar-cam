#!/usr/bin/env python3
"""LIVE P4P knock (0x130b) with a FRESHLY generated randomID + conv, cold (no prior
lanstreamreq). Sends 0x1309 (channel open) first, then the knock on the session port.

Background: p4p_device_auth is a plaintext memcmp of UID + view-pw + "admin" (all held),
so replays failed only because they reused a STALE randomID that matched no live session.
This uses fresh IDs. If the knock still returns 0x130c status=0xffff, the channel slot the
knock needs (chanstruct[0xc]==conv, chanstruct[0x17]==header[0xf]) was not allocated by a
cold 0x1309 -- use knock_after_stream.py instead (lanstreamreq allocates it).

Config from env or local/device.json via p4p_probe_config. Camera FREE. Read-only: UDP.
"""
import os, sys, time, struct, socket
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p4p_probe_config as cfg
from p4p.lansearch import discover, LAN_SEARCH_PORT
from p4p.packet import MAGIC, build
from p4p.crypto import decode, encode
from p4p.kcp import KcpReceiver
from p4p.client import extract_h264

CAM, BC, UID = cfg.CAMERA_IP, cfg.BROADCAST, cfg.UID

def mt(d): return struct.unpack_from("<H", d, 8)[0]
def status_of(dd): return dd[36:38].hex() if len(dd) >= 38 else "??"

def build_ioctrl(iotype, data12, idx, seq, aux=0x21):
    body = bytearray(24); body[0] = 3
    struct.pack_into("<H", body, 4, seq & 0xffff); struct.pack_into("<H", body, 6, 12)
    struct.pack_into("<I", body, 8, iotype); body[12:24] = data12
    hdr = MAGIC + struct.pack("<HHHH", len(body), 0, 0x1401, aux) + struct.pack("<HBB", idx & 0xffff, 0, 0)
    return encode(hdr + bytes(body))

def main():
    if not discover(UID, targets=[BC, CAM], timeout=15.0):
        raise SystemExit("camera not found (free it: disable HA integration)")
    print("camera awake via LAN-search")

    rid  = os.urandom(3) + bytes([os.urandom(1)[0] or 1])   # fresh, nonzero
    conv = os.urandom(4); convI = int.from_bytes(conv, "little")
    print(f"fresh randomID={rid.hex()}  conv={conv.hex()} (0x{convI:08x})")

    stream  = encode(cfg.build_stream(rid, conv))
    knock   = encode(cfg.build_knock(rid, conv))
    confirm = encode(cfg.build_confirm(rid, conv))
    alive   = encode(cfg.build_alive_msg(rid, conv))

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("", 0)); s.settimeout(0.4)

    # step 1: 0x1309 opens the channel; learn the session port
    sess_port = None
    for _ in range(5): s.sendto(stream, (CAM, LAN_SEARCH_PORT)); time.sleep(0.12)
    t = time.monotonic() + 2.5
    while time.monotonic() < t:
        try: d, a = s.recvfrom(65535)
        except socket.timeout: continue
        try: dd = decode(d)
        except Exception: continue
        if dd[:4] != MAGIC: continue
        if sess_port is None: sess_port = a[1]
        print(f"<- {hex(mt(dd))} from {a[1]}  status={status_of(dd) if mt(dd)==0x130c else '-'}")
    port = sess_port or LAN_SEARCH_PORT
    print(f"session port = {port}")

    # step 2: knock on the session port, check status flip
    c130c = None
    for _ in range(5): s.sendto(knock, (CAM, port)); time.sleep(0.12)
    t = time.monotonic() + 2.5
    while time.monotonic() < t:
        try: d, a = s.recvfrom(65535)
        except socket.timeout: continue
        try: dd = decode(d)
        except Exception: continue
        if dd[:4] != MAGIC or mt(dd) != 0x130c: continue
        c130c = dd
        print(f"<- 0x130c from {a[1]}  STATUS={status_of(dd)}  (ffff=fail, else=PASS)")
    if c130c is None:
        print("no 0x130c after 1309+knock"); s.close(); return
    if status_of(c130c) == "ffff":
        print(">>> STILL ffff cold; use knock_after_stream.py (lanstreamreq allocates the slot)")
    else:
        print(">>> STATUS FLIPPED — auth+channel PASSED, proceeding to ioctrl")

    # step 3: confirm + try video/ioctrl
    if sess_port:
        for _ in range(3): s.sendto(confirm, (CAM, sess_port)); time.sleep(0.05)
    kcp = KcpReceiver(convI); idx = None; acks = frsp = 0
    t = time.monotonic() + 6; last = 0; seq = 0; sent_io = False
    while time.monotonic() < t:
        now = time.monotonic()
        if now - last > 0.6: s.sendto(alive, (CAM, port)); last = now
        if idx is not None and not sent_io:
            ptz = bytearray(12); ptz[5] = 3; ptz[6] = 8
            s.sendto(build_ioctrl(4097, bytes(ptz), idx, seq), (CAM, port)); seq += 1
            s.sendto(build_ioctrl(4864, bytes(12), idx, seq), (CAM, port)); seq += 1
            sent_io = True; print("   sent PTZ(4097) + FILE_LIST(4864)")
        try: d, a = s.recvfrom(65535)
        except socket.timeout: continue
        try: dd = decode(d)
        except Exception: continue
        if dd[:4] != MAGIC: continue
        m = mt(dd)
        if m == 0x1402: acks += 1
        if m in (0x4865, 0x1403): frsp += 1
        if m != 0x140A: continue
        if idx is None: idx = struct.unpack_from("<H", dd, 0xc)[0]; print(f"   VIDEO! session index={idx}")
        kcp.input(dd[16:16+struct.unpack_from('<H', dd, 4)[0]])
        for msg in kcp.messages(): extract_h264(msg)
        ak = kcp.ack_segments()
        for i in range(0, len(ak), 8): s.sendto(build(0x1409, b"".join(ak[i:i+8]), aux=0x21), (CAM, port))
    print(f"\nsummary: video-frames-seen={idx is not None} 0x1402-acks={acks} file-rsp={frsp}")
    print("acks>0 -> ioctrl accepted (auth worked). video but 0 acks -> still no ioctrl receiver.")
    s.close()

main()
