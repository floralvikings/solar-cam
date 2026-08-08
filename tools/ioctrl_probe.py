#!/usr/bin/env python3
"""Decisive test: does the local ioctrl channel answer ANY non-video request?

On a properly-established session (knock 0x130b + confirm 0x130d, index from
resp[0x47]) fire several GET/LIST ioctrls that SHOULD reply, and scan every KCP
PUSH segment for any ioctrl-response frame (leading type word != 0x11 video).
If we see a RESP iotype (809/817/833/793/837...), the channel does real work and
an over-the-wire FILE_DOWNLOAD dump is worth pursuing. If only video/telemetry
comes back, the local ioctrl is a dead end -> UART. Camera FREE. Read-only.
"""
import os, sys, time, struct, socket
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p4p_probe_config as cfg
from p4p.lansearch import discover, LAN_SEARCH_PORT
from p4p.session import build_lanstreamreq, parse_lanstreamrsp, build_alive
from p4p.packet import MAGIC, build
from p4p.crypto import decode, encode
from p4p.kcp import KcpReceiver, _HDR
from p4p_ext import KcpSender, build_ioctrl_frame

CAM, ME, BC, UID = cfg.CAMERA_IP, cfg.CLIENT_IP, cfg.BROADCAST, cfg.UID
# (iotype, label, request-data)
REQUESTS = [
    (808, "GETSUPPORTSTREAM", b"\x00\x00\x00\x00"),
    (816, "DEVINFO",          b"\x00\x00\x00\x00"),
    (832, "LISTWIFIAP",       b""),
    (836, "GETWIFI",          b"\x00\x00\x00\x00"),
    (792, "LISTEVENT",        bytes(24)),                # channel 0 + zero time range
    (808 + 1, "GETRESOLVE?",  b"\x00\x00\x00\x00"),
]
RESP_NAMES = {809: "GETSUPPORTSTREAM_RESP", 817: "DEVINFO_RESP", 833: "LISTWIFIAP_RESP",
              793: "LISTEVENT_RESP", 837: "GETWIFI_RESP", 4096: "PTZ_RESP", 795: "PLAYCTRL_RESP"}

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
    if ok != "0000": raise SystemExit(f"knock failed ({ok}) — camera busy/degraded")
    for _ in range(4): s.sendto(encode(cfg.build_confirm(os.urandom(4), conv_le, 0x00, index)), (CAM, sport)); time.sleep(0.08)
    return conv, index, sport, avidx, rcv

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("", 0)); s.settimeout(0.15)
    myport = s.getsockname()[1]
    conv, index, sport, avidx, rcv = setup(s, myport)
    print(f"session ready (index={index}, avidx={avidx}) — firing GET/LIST requests\n")
    snd = KcpSender(conv)

    def send(iotype, data, label):
        seg = snd.push(build_ioctrl_frame(avidx, iotype, data), una=rcv.rcv_nxt, ts=ms())
        s.sendto(build(0x1409, seg, aux=0x21), (CAM, sport)); print(f"  -> req {label} io={iotype} dlen={len(data)}")

    responses = {}   # iotype -> count
    other = []       # non-video control frames seen (lead, iotype, hex)
    acks = set()
    t0 = time.monotonic(); last_alive = last_rtx = 0; ri = 0; last_req = 0
    while time.monotonic() < t0 + 14:
        now = time.monotonic()
        # fire one request every ~1.2s, cycling the list twice
        if ri < len(REQUESTS)*2 and now-last_req > 1.2:
            iot, lbl, data = REQUESTS[ri % len(REQUESTS)]; send(iot, data, lbl); ri += 1; last_req = now
        if now-last_alive > 0.6: s.sendto(build_alive(conv), (CAM, sport)); last_alive = now
        if now-last_rtx > 0.4:
            for sg in snd.retransmit_segments(): s.sendto(build(0x1409, sg, aux=0x21), (CAM, sport))
            last_rtx = now
        try: d, _ = s.recvfrom(65535)
        except socket.timeout: continue
        try: dd = decode(d)
        except Exception: continue
        if dd[:4] != MAGIC: continue
        if mt(dd) == 0x1402:
            print(f"  <- RAW 0x1402: {dd[16:16+24].hex()}")
        if mt(dd) not in (0x140A, 0x1409): continue
        body = dd[16:16+struct.unpack_from('<H', dd, 4)[0]]
        acks.update(snd.note_acks(body))
        # scan every PUSH segment for non-video control frames
        off = 0; n = len(body)
        while n-off >= _HDR.size:
            c, cmd, frg, wnd, ts, sn, una, ln = _HDR.unpack_from(body, off)
            pl = body[off+_HDR.size:off+_HDR.size+ln]; off += _HDR.size+ln
            if c != conv or cmd != 81 or len(pl) < 0x10: continue
            lead = struct.unpack_from("<I", pl, 0)[0]
            if lead == 0x11: continue                 # video / periodic telemetry
            iotype = struct.unpack_from("<I", pl, 0xc)[0] if len(pl) >= 0x10 else -1
            responses[iotype] = responses.get(iotype, 0) + 1
            if len(other) < 30: other.append((lead, iotype, pl[:28].hex()))
        rcv.input(body); rcv.messages()
        ak = rcv.ack_segments()
        for i in range(0, len(ak), 8): s.sendto(build(0x1409, b"".join(ak[i:i+8]), aux=0x21), (CAM, sport))
    s.close()

    print(f"\n===== RESULT =====")
    print(f"KCP acks: {'yes ('+str(len(acks))+')' if acks else 'NONE'}")
    print(f"non-video control frames by iotype: " +
          (", ".join(f"{RESP_NAMES.get(i, '?')}={i}(x{c})" for i, c in sorted(responses.items())) if responses else "NONE"))
    for lead, iot, hx in other[:12]:
        print(f"    lead=0x{lead:x} iotype={iot} ({RESP_NAMES.get(iot,'?')}): {hx}")
    known = [i for i in responses if i in RESP_NAMES and i != 4096]
    if known:
        print(f"\n>>> LOCAL IOCTRL RESPONDS to {[RESP_NAMES[i] for i in known]} — over-the-wire dump worth pursuing")
    else:
        print("\n>>> No non-video ioctrl responses — local ioctrl is video-only; over-the-wire firmware dump is a DEAD END. Use UART.")

main()
