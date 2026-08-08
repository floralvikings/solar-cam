#!/usr/bin/env python3
"""Snapshot sweep: try N PTZ command encodings in one session, grab a keyframe
after each, and PIL-diff every frame against 'before' to detect any pan
objectively. If no encoding shifts the view, local ioctrl doesn't drive the motor.
Camera must be FREE. Config from env/local/device.json.
"""
import os, sys, time, struct, socket, subprocess, shutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p4p_probe_config as cfg
from p4p.lansearch import discover, LAN_SEARCH_PORT
from p4p.session import build_lanstreamreq, parse_lanstreamrsp, build_alive
from p4p.packet import MAGIC, build
from p4p.crypto import decode, encode
from p4p.kcp import KcpReceiver, KcpSender, build_ioctrl_frame
from p4p.client import extract_h264, _has_sps
from PIL import Image, ImageChops

CAM, ME, BC, UID = cfg.CAMERA_IP, cfg.CLIENT_IP, cfg.BROADCAST, cfg.UID
PTZ_REQ = 4097
OUT = "/Users/cbrinkman/.claude/jobs/0eb50487/tmp"
FF = shutil.which("ffmpeg") or "/usr/local/bin/ffmpeg"

# 5 candidate PTZ data encodings (all aiming to pan RIGHT, away from the limit).
# label -> 8-byte data. Vary control-byte position, opcode set, speed.
ENCODINGS = [
    ("ctrl@1=3 spd@5=8  (ENUM right)",  bytes([0, 3, 0, 0, 0, 8, 0, 0])),
    ("ctrl@1=6 spd@5=8  (top right)",   bytes([0, 6, 0, 0, 0, 8, 0, 0])),
    ("ctrl@0=3 spd@1=8",                bytes([3, 8, 0, 0, 0, 0, 0, 0])),
    ("ctrl@2=3 spd@3=8",                bytes([0, 0, 3, 8, 0, 0, 0, 0])),
    ("ctrl@1=3 spd@5=63 (max speed)",   bytes([0, 3, 0, 0, 0, 63, 0, 0])),
]

def mt(d): return struct.unpack_from("<H", d, 8)[0]
def stt(dd): return dd[36:38].hex() if len(dd) >= 38 else "??"
def ms(): return int(time.monotonic()*1000) & 0xffffffff

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
    if not sport: raise SystemExit("no 0x1308 (camera busy? free it)")
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
    if ok != "0000": raise SystemExit(f"knock failed ({ok})")
    for _ in range(4): s.sendto(encode(cfg.build_confirm(os.urandom(4), conv_le, 0x00, index)), (CAM, sport)); time.sleep(0.08)
    return conv, index, sport, avidx, rcv

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("", 0)); s.settimeout(0.15)
    myport = s.getsockname()[1]
    conv, index, sport, avidx, rcv = setup(s, myport)
    print(f"session ready (index={index}, avidx={avidx})")
    snd = KcpSender(conv)

    names = ["before"] + [f"e{i}" for i in range(len(ENCODINGS))]
    bufs = {n: bytearray() for n in names}
    started = {n: False for n in names}
    plan = []  # (t0, t1, action)
    t = 0.0
    plan.append((t, t+2.0, ("collect", "before"))); t += 2.0
    for i, (_lbl, data) in enumerate(ENCODINGS):
        plan.append((t, t+2.5, ("pan", data))); t += 2.5
        plan.append((t, t+2.0, ("collect", f"e{i}"))); t += 2.0

    t0 = time.monotonic(); last_alive = last_cmd = last_rtx = 0; acks = set()
    end = t0 + plan[-1][1] + 0.5
    while time.monotonic() < end:
        now = time.monotonic(); el = now - t0
        act = next((a[2] for a in plan if a[0] <= el < a[1]), None)
        if act and act[0] == "pan" and now-last_cmd > 0.4:
            seg = snd.push(build_ioctrl_frame(avidx, PTZ_REQ, act[1]), una=rcv.rcv_nxt, ts=ms())
            s.sendto(build(0x1409, seg, aux=0x21), (CAM, sport)); last_cmd = now
        if now-last_alive > 0.6: s.sendto(build_alive(conv), (CAM, sport)); last_alive = now
        if now-last_rtx > 0.4:
            for sg in snd.retransmit_segments(): s.sendto(build(0x1409, sg, aux=0x21), (CAM, sport))
            last_rtx = now
        try: d, _ = s.recvfrom(65535)
        except socket.timeout: continue
        try: dd = decode(d)
        except Exception: continue
        if dd[:4] != MAGIC or mt(dd) not in (0x140A, 0x1409): continue
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
    print(f"KCP acks: {'yes ('+str(len(acks))+')' if acks else 'NONE'}")

    for n in names:
        open(os.path.join(OUT, f"sweep_{n}.h264"), "wb").write(bufs[n])
    imgs = {}
    for n in names:
        h = os.path.join(OUT, f"sweep_{n}.h264"); j = os.path.join(OUT, f"sweep_{n}.jpg")
        if os.path.exists(j): os.remove(j)
        subprocess.run([FF, "-y", "-loglevel", "error", "-f", "h264", "-i", h,
                        "-frames:v", "1", j], capture_output=True)
        imgs[n] = j if os.path.exists(j) and os.path.getsize(j) > 0 else None

    print("\n=== movement vs 'before' (mean abs pixel diff, 0=identical) ===")
    base = imgs.get("before")
    ref = Image.open(base).convert("L") if base else None
    for i, (lbl, _data) in enumerate(ENCODINGS):
        p = imgs.get(f"e{i}")
        if ref is None or p is None:
            print(f"  E{i} [{lbl}]: (missing image)"); continue
        im = Image.open(p).convert("L").resize(ref.size)
        diff = ImageChops.difference(ref, im)
        mad = sum(b*c for b, c in enumerate(diff.histogram())) / (im.size[0]*im.size[1])
        moved = "  <<< MOVED?" if mad > 6.0 else ""
        print(f"  E{i} [{lbl}]: MAD={mad:.2f}{moved}")
    print("\nJPEGs: " + OUT + "/sweep_*.jpg")

main()
