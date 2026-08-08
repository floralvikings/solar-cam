#!/usr/bin/env python3
"""Watchable PTZ sweep: full handshake, then pan LEFT/RIGHT repeatedly (~30s) so a
human can SEE the camera move. Ends roughly centered (equal L/R). Counts the
camera's PTZ_COMMAND_RESP (iotype 4096) echoes per phase as protocol confirmation.

Recipe (all solved): lanstreamreq -> index(resp[0x46]) -> video -> knock 0x130b ->
confirm 0x130d -> ioctrl over KCP (type-3 frame, PTZ iotype 4097).
Config from env/local/device.json. Camera FREE. UDP only.
"""
import os, sys, time, struct, socket
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p4p_probe_config as cfg
from p4p.lansearch import discover, LAN_SEARCH_PORT
from p4p.session import build_lanstreamreq, parse_lanstreamrsp, build_alive
from p4p.packet import MAGIC, build
from p4p.crypto import decode, encode
from p4p.kcp import KcpReceiver, KcpSender, build_ioctrl_frame

CAM, ME, BC, UID = cfg.CAMERA_IP, cfg.CLIENT_IP, cfg.BROADCAST, cfg.UID
PTZ_REQ, PTZ_RESP = 4097, 4096
LEFT, RIGHT, STOP = 6, 3, 0

def mt(d): return struct.unpack_from("<H", d, 8)[0]
def st(dd): return dd[36:38].hex() if len(dd) >= 38 else "??"
def ms(): return int(time.monotonic() * 1000) & 0xffffffff
def ptz(control, speed=8): return bytes([0, control & 0xff, 0, 0, 0, speed & 0xff, 0, 0])

def resp_iotype(msg):
    # device->client ioctrl response: [0:4]=type(4) [8:12]=dlen [0xc:0x10]=iotype
    if len(msg) >= 0x10 and struct.unpack_from("<I", msg, 0)[0] == 4:
        return struct.unpack_from("<I", msg, 0xc)[0], msg[0x10:0x10+struct.unpack_from("<I", msg, 8)[0]]
    return None

def main():
    infos = discover(UID, targets=[BC, CAM], timeout=15.0)
    if not infos: raise SystemExit("camera not found (free it: disable HA integration)")
    pw = (infos[0].credential or cfg.VIEW_PW).encode()
    conv = int.from_bytes(os.urandom(4), "little"); conv_le = conv.to_bytes(4, "little")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("", 0)); s.settimeout(0.15)
    myport = s.getsockname()[1]

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
        if dd[:4] == MAGIC and mt(dd) == 0x130c: ok = st(dd)
    if ok != "0000": raise SystemExit(f"knock failed ({ok})")
    for _ in range(4): s.sendto(encode(cfg.build_confirm(os.urandom(4), conv_le, 0x00, index)), (CAM, sport)); time.sleep(0.08)
    print(f"session established (index={index}, sport={sport}) — starting sweep\n")

    snd = KcpSender(conv)
    def send(control):
        seg = snd.push(build_ioctrl_frame(avidx, PTZ_REQ, ptz(control)), una=rcv.rcv_nxt, ts=ms())
        s.sendto(build(0x1409, seg, aux=0x21), (CAM, sport))
    resp = {LEFT: 0, RIGHT: 0, STOP: 0}
    def pump(seconds, keepdir=None):
        end = time.monotonic() + seconds; la = lr = lc = 0
        while time.monotonic() < end:
            now = time.monotonic()
            if keepdir is not None and now - lc > 0.4: send(keepdir); lc = now
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
            snd.note_acks(body); rcv.input(body)
            for msg in rcv.messages():
                r = resp_iotype(msg)
                if r and r[0] == PTZ_RESP and len(r[1]) >= 1: resp[r[1][0]] = resp.get(r[1][0], 0) + 1
            ak = rcv.ack_segments()
            for i in range(0, len(ak), 8): s.sendto(build(0x1409, b"".join(ak[i:i+8]), aux=0x21), (CAM, sport))

    for rnd in range(1, 4):
        print(f"round {rnd}/3:  <<< PANNING LEFT")
        send(LEFT); pump(4.0, keepdir=LEFT); send(STOP); pump(0.6)
        print(f"round {rnd}/3:  PANNING RIGHT >>>")
        send(RIGHT); pump(4.0, keepdir=RIGHT); send(STOP); pump(0.8)
    send(STOP); pump(0.5)
    print(f"\nsweep done. PTZ_COMMAND_RESP echoes by control code: "
          f"LEFT(6)={resp.get(6,0)} RIGHT(3)={resp.get(3,0)} STOP(0)={resp.get(0,0)}")
    print("If the camera physically panned left then right each round, local PTZ is fully working.")
    s.close()

main()
