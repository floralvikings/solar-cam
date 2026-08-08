#!/usr/bin/env python3
"""Definitive PTZ diagnostic: send each direction once (well-spaced) and read the
camera's PTZ_RESP (iotype 4096) state by scanning KCP PUSH segments DIRECTLY --
bypassing in-order reassembly, which head-of-line-blocks behind video gaps.

If the camera's reported state tracks each command (LEFT->6, RIGHT->3, UP->1,
DOWN->2, STOP->0), the ioctrl command path is processed by the camera app.
Config from env/local/device.json. Camera FREE. Watch it too if you can.
"""
import os, sys, time, struct, socket
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p4p_probe_config as cfg
from p4p.lansearch import discover, LAN_SEARCH_PORT
from p4p.session import build_lanstreamreq, parse_lanstreamrsp, build_alive
from p4p.packet import MAGIC, build
from p4p.crypto import decode, encode
from p4p.kcp import KcpReceiver, KcpSender, build_ioctrl_frame, _HDR

CAM, ME, BC, UID = cfg.CAMERA_IP, cfg.CLIENT_IP, cfg.BROADCAST, cfg.UID
PTZ_REQ, PTZ_RESP = 4097, 4096
NAME = {6: "LEFT", 3: "RIGHT", 1: "UP", 2: "DOWN", 0: "STOP"}

def mt(d): return struct.unpack_from("<H", d, 8)[0]
def stt(dd): return dd[36:38].hex() if len(dd) >= 38 else "??"
def ms(): return int(time.monotonic() * 1000) & 0xffffffff
def ptz(c, speed=8): return bytes([0, c & 0xff, 0, 0, 0, speed & 0xff, 0, 0])

def scan_ptz_states(conv, body):
    """Yield PTZ_RESP state bytes from every type-4/iotype-4096 PUSH segment,
    ignoring sn order (so video HoL never hides an ioctrl response)."""
    off = 0; n = len(body)
    while n - off >= _HDR.size:
        c, cmd, frg, wnd, ts, sn, una, ln = _HDR.unpack_from(body, off)
        pl = body[off + _HDR.size: off + _HDR.size + ln]; off += _HDR.size + ln
        if c != conv or cmd != 81 or len(pl) < 0x14: continue
        if struct.unpack_from("<I", pl, 0)[0] == 4 and struct.unpack_from("<I", pl, 0xc)[0] == PTZ_RESP:
            yield pl[0x10]

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("", 0)); s.settimeout(0.15)
    myport = s.getsockname()[1]
    infos = discover(UID, targets=[BC, CAM], timeout=15.0)
    if not infos: raise SystemExit("camera not found (free it)")
    pw = (infos[0].credential or cfg.VIEW_PW).encode()
    conv = int.from_bytes(os.urandom(4), "little"); conv_le = conv.to_bytes(4, "little")
    lsr = build_lanstreamreq(UID, conv=conv, password=pw, client_ip=ME, client_port=myport)
    sport = rsp = None
    for _ in range(6): s.sendto(lsr, (CAM, LAN_SEARCH_PORT)); time.sleep(0.1)
    t = time.monotonic() + 3
    while time.monotonic() < t and rsp is None:
        try: d, _ = s.recvfrom(65535)
        except socket.timeout: break
        if d == lsr: continue
        try:
            dd = decode(d)
            if dd[:4] == MAGIC and mt(dd) == 0x1308: rsp = dd; sport = parse_lanstreamrsp(dd).session_port
        except Exception: pass
    if not sport: raise SystemExit("no 0x1308")
    index = rsp[0x46]
    rcv = KcpReceiver(conv); avidx = None
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
        if avidx is None: avidx = struct.unpack_from("<H", dd, 0xc)[0]
        rcv.input(dd[16:16+struct.unpack_from('<H', dd, 4)[0]]); rcv.messages()
        ak = rcv.ack_segments()
        for i in range(0, len(ak), 8): s.sendto(build(0x1409, b"".join(ak[i:i+8]), aux=0x21), (CAM, sport))
    if avidx is None: avidx = 0
    ok = None
    for _ in range(4): s.sendto(encode(cfg.build_knock(os.urandom(4), conv_le, 0x00, index)), (CAM, sport)); time.sleep(0.1)
    t = time.monotonic() + 1.2
    while time.monotonic() < t:
        try: d, _ = s.recvfrom(65535)
        except socket.timeout: continue
        try: dd = decode(d)
        except Exception: continue
        if dd[:4] == MAGIC and mt(dd) == 0x130c: ok = stt(dd)
    if ok != "0000": raise SystemExit(f"knock failed ({ok})")
    for _ in range(4): s.sendto(encode(cfg.build_confirm(os.urandom(4), conv_le, 0x00, index)), (CAM, sport)); time.sleep(0.08)
    print(f"session established (index={index} sport={sport}) — probing directions\n")
    print("########  WATCH THE CAMERA NOW — LEFT, RIGHT, UP, DOWN, each ~3s  ########\n")

    snd = KcpSender(conv)
    def send(c):
        seg = snd.push(build_ioctrl_frame(avidx, PTZ_REQ, ptz(c)), una=rcv.rcv_nxt, ts=ms())
        s.sendto(build(0x1409, seg, aux=0x21), (CAM, sport))
    def run(seconds, resend=None):
        states = []; end = time.monotonic() + seconds; la = lr = ls = 0
        while time.monotonic() < end:
            now = time.monotonic()
            if resend is not None and now - ls > 1.0: send(resend); ls = now
            if now - la > 0.5: s.sendto(build_alive(conv), (CAM, sport)); la = now
            if now - lr > 0.4:
                for sg in snd.retransmit_segments(): s.sendto(build(0x1409, sg, aux=0x21), (CAM, sport))
                lr = now
            try: d, _ = s.recvfrom(65535)
            except socket.timeout: continue
            try: dd = decode(d)
            except Exception: continue
            if dd[:4] != MAGIC or mt(dd) not in (0x140A, 0x1409): continue
            body = dd[16:16+struct.unpack_from('<H', dd, 4)[0]]
            for stv in scan_ptz_states(conv, body):
                states.append(stv)
            snd.note_acks(body); rcv.input(body); rcv.messages()
            ak = rcv.ack_segments()
            for i in range(0, len(ak), 8): s.sendto(build(0x1409, b"".join(ak[i:i+8]), aux=0x21), (CAM, sport))
        return states

    results = {}
    for c in (6, 3, 1, 2):   # LEFT RIGHT UP DOWN
        print(f">>> {NAME[c]}")
        send(c); st = run(3.0, resend=c)
        send(0); run(1.5)
        from collections import Counter
        results[NAME[c]] = Counter(NAME.get(v, v) for v in st)
        print(f"    states seen during {NAME[c]}: {dict(results[NAME[c]])}")

    print("\n===== DIAGNOSIS =====")
    for k, v in results.items():
        tracked = any(state == k for state in v)
        print(f"  {k:5}: {'REGISTERED (state matched)' if tracked else 'idle only'}   {dict(v)}")
    any_tracked = any(any(st == k for st in v) for k, v in results.items())
    print(f"\n>>> camera registered at least one direction: {any_tracked}")
    s.close()

main()
