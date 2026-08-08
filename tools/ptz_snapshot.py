#!/usr/bin/env python3
"""Prove PTZ by comparing frames: grab a keyframe BEFORE, pan LEFT, grab one, pan
RIGHT, grab one. Decode each to JPEG with ffmpeg. If the camera pans, the field of
view visibly shifts between the images. Needs the camera FREE (no other session).
Config from env/local/device.json.
"""
import os, sys, time, struct, socket, subprocess, shutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p4p_probe_config as cfg
from p4p.lansearch import discover, LAN_SEARCH_PORT
from p4p.session import build_lanstreamreq, parse_lanstreamrsp, build_alive
from p4p.packet import MAGIC, build
from p4p.crypto import decode, encode
from p4p.kcp import KcpReceiver
from p4p_ext import KcpSender, build_ioctrl_frame
from p4p.client import extract_h264, _has_sps

CAM, ME, BC, UID = cfg.CAMERA_IP, cfg.CLIENT_IP, cfg.BROADCAST, cfg.UID
PTZ_REQ = 4097
LEFT, RIGHT, STOP = 6, 3, 0
OUT = "/Users/cbrinkman/.claude/jobs/0eb50487/tmp"
FF = shutil.which("ffmpeg") or next((p for p in
    ("/usr/local/bin/ffmpeg", "/opt/homebrew/bin/ffmpeg", "/usr/bin/ffmpeg")
    if os.path.exists(p)), "ffmpeg")

def mt(d): return struct.unpack_from("<H", d, 8)[0]
def stt(dd): return dd[36:38].hex() if len(dd) >= 38 else "??"
def ms(): return int(time.monotonic()*1000) & 0xffffffff
# GROUND TRUTH from captured phone->camera traffic (rbx-cloud-ptz2.pcap):
# 12-byte payload, control at [5], speed at [6], flag 0x01 at [10].
def ptz(c, sp=8): return bytes([0,0,0,0,0, c & 0xff, sp & 0xff, 0, 0,0, 1, 0])

def setup(s, myport):
    infos = discover(UID, targets=[BC, CAM], timeout=15.0)
    if not infos: raise SystemExit("camera not found")
    pw = (infos[0].credential or cfg.VIEW_PW).encode()
    conv = int.from_bytes(os.urandom(4), "little"); conv_le = conv.to_bytes(4, "little")
    lsr = build_lanstreamreq(UID, conv=conv, password=pw, client_ip=ME, client_port=myport)
    sport = rsp = None
    for _ in range(6): s.sendto(lsr, (CAM, LAN_SEARCH_PORT)); time.sleep(0.1)
    t = time.monotonic()+3
    while time.monotonic() < t and rsp is None:
        try: d, _ = s.recvfrom(65535)
        except socket.timeout: break
        if d == lsr: continue
        try:
            dd = decode(d)
            if dd[:4] == MAGIC and mt(dd) == 0x1308: rsp = dd; sport = parse_lanstreamrsp(dd).session_port
        except Exception: pass
    if not sport: raise SystemExit("no 0x1308 (camera busy? close all live views + disable HA)")
    index = rsp[0x47]
    rcv = KcpReceiver(conv); avidx = None
    for _ in range(3): s.sendto(build_alive(conv), (CAM, sport))
    t = time.monotonic()+3; last = 0
    while time.monotonic() < t:
        now = time.monotonic()
        if now-last > 0.7: s.sendto(build_alive(conv), (CAM, sport)); last = now
        try: d, _ = s.recvfrom(65535)
        except socket.timeout: continue
        try: dd = decode(d)
        except Exception: continue
        if dd[:4] != MAGIC or mt(dd) != 0x140A: continue
        if avidx is None: avidx = struct.unpack_from("<H", dd, 0xc)[0]
        rcv.input(dd[16:16+struct.unpack_from('<H', dd, 4)[0]]); rcv.messages()
        ak = rcv.ack_segments()
        for i in range(0, len(ak), 8): s.sendto(build(0x1409, b"".join(ak[i:i+8]), aux=0x21), (CAM, sport))
    if avidx is None: avidx = 0
    ok = None
    for _ in range(4): s.sendto(encode(cfg.build_knock(os.urandom(4), conv_le, 0x00, index)), (CAM, sport)); time.sleep(0.1)
    t = time.monotonic()+1.2
    while time.monotonic() < t:
        try: d, _ = s.recvfrom(65535)
        except socket.timeout: continue
        try: dd = decode(d)
        except Exception: continue
        if dd[:4] == MAGIC and mt(dd) == 0x130c: ok = stt(dd)
    if ok != "0000": raise SystemExit(f"knock failed ({ok}) — camera busy/degraded")
    for _ in range(4): s.sendto(encode(cfg.build_confirm(os.urandom(4), conv_le, 0x00, index)), (CAM, sport)); time.sleep(0.08)
    return conv, index, sport, avidx, rcv

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("", 0)); s.settimeout(0.15)
    myport = s.getsockname()[1]
    conv, index, sport, avidx, rcv = setup(s, myport)
    print(f"session ready (index={index}, avidx={avidx})")
    snd = KcpSender(conv)

    # timeline: collect windows [start,end], and pan windows with a direction
    bufs = {"before": bytearray(), "left": bytearray(), "right": bytearray()}
    started = {k: False for k in bufs}
    # (t0, t1, action)  action: ("collect", name) | ("pan", dir) | ("stop",)
    plan = [
        (0.0, 2.5, ("collect", "before")),
        (2.5, 6.0, ("pan", LEFT)),
        (6.0, 6.6, ("stop",)),
        (6.6, 9.1, ("collect", "left")),
        (9.1, 14.0, ("pan", RIGHT)),   # longer, to go back past center
        (14.0, 14.6, ("stop",)),
        (14.6, 17.1, ("collect", "right")),
    ]
    t0 = time.monotonic(); last_alive = last_cmd = last_rtx = 0; acks = set()
    end = t0 + plan[-1][1] + 0.5
    while time.monotonic() < end:
        now = time.monotonic(); el = now - t0
        act = None
        for a, b, action in plan:
            if a <= el < b: act = action; break
        if act and act[0] == "pan" and now-last_cmd > 0.3:
            seg = snd.push(build_ioctrl_frame(avidx, PTZ_REQ, ptz(act[1])), una=rcv.rcv_nxt, ts=ms())
            s.sendto(build(0x1409, seg, aux=0x21), (CAM, sport)); last_cmd = now
        if act and act[0] == "stop" and now-last_cmd > 0.2:
            seg = snd.push(build_ioctrl_frame(avidx, PTZ_REQ, ptz(STOP)), una=rcv.rcv_nxt, ts=ms())
            s.sendto(build(0x1409, seg, aux=0x21), (CAM, sport)); last_cmd = now
        if now-last_alive > 0.6: s.sendto(build_alive(conv), (CAM, sport)); last_alive = now
        if now-last_rtx > 0.4:
            for sg in snd.retransmit_segments(): s.sendto(build(0x1409, sg, aux=0x21), (CAM, sport))
            last_rtx = now
        try: d, _ = s.recvfrom(65535)
        except socket.timeout: continue
        try: dd = decode(d)
        except Exception: continue
        if dd[:4] != MAGIC: continue
        if mt(dd) not in (0x140A, 0x1409): continue
        body = dd[16:16+struct.unpack_from('<H', dd, 4)[0]]
        acks.update(snd.note_acks(body))
        rcv.input(body)
        for msg in rcv.messages():
            fr = extract_h264(msg)
            if not fr: continue
            if act and act[0] == "collect":
                name = act[1]
                if not started[name]:
                    if _has_sps(fr): started[name] = True
                    else: continue
                bufs[name] += fr
        ak = rcv.ack_segments()
        for i in range(0, len(ak), 8): s.sendto(build(0x1409, b"".join(ak[i:i+8]), aux=0x21), (CAM, sport))
    s.close()

    print(f"clip bytes: " + " ".join(f"{k}={len(v)}" for k, v in bufs.items()))
    print(f"KCP acks: {'yes ('+str(len(acks))+' segs)' if acks else 'NONE — session likely contended'}")
    # write ALL clips first, so a decode failure never loses data
    for name, buf in bufs.items():
        open(os.path.join(OUT, f"{name}.h264"), "wb").write(buf)
    print(f"ffmpeg = {FF}")
    results = {}
    for name in bufs:
        h = os.path.join(OUT, f"{name}.h264"); j = os.path.join(OUT, f"{name}.jpg")
        if os.path.exists(j): os.remove(j)
        r = subprocess.run([FF, "-y", "-loglevel", "error", "-f", "h264", "-i", h,
                            "-frames:v", "1", j], capture_output=True)
        ok = os.path.exists(j) and os.path.getsize(j) > 0
        results[name] = j if ok else None
        print(f"  {name}: {'JPEG '+j if ok else 'decode FAILED '+r.stderr.decode()[:120]}")
    print("\nRESULT:", {k: (v or 'none') for k, v in results.items()})

main()
