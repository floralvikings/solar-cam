#!/usr/bin/env python3
"""Comprehensive ioctrl diagnostic: complete the 2-step knock handshake, then probe
BOTH ioctrl transports (KCP + raw 0x1401) with a request that must answer.

Flow: lanstreamreq -> index(resp[0x46]) -> video up -> knock(0x130b) PASS ->
CONFIRM(0x130d) [sets slot[0x19]=0 = established] -> DEVINFO_REQ over KCP AND raw
0x1401 -> log EVERYTHING coming back (all msgtypes, every small KCP message, raw
0x1402, device KCP-acks). DEVINFO_RESP(817) = the app-layer ioctrl handler ran.

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
DEVINFO_REQ, DEVINFO_RESP = 816, 817
PTZ_REQ = 4097
PTZ_LEFT, PTZ_RIGHT, PTZ_STOP = 6, 3, 0

def mt(d): return struct.unpack_from("<H", d, 8)[0]
def status_of(dd): return dd[36:38].hex() if len(dd) >= 38 else "??"
def ms(): return int(time.monotonic() * 1000) & 0xffffffff

def raw_ioctrl(iotype, data, sessidx, seq):
    body = bytearray(0xc + len(data)); body[0] = 3
    struct.pack_into("<H", body, 4, seq & 0xffff)
    struct.pack_into("<H", body, 6, len(data))
    struct.pack_into("<I", body, 8, iotype)
    body[0xc:] = data
    hdr = MAGIC + struct.pack("<HHHH", len(body), 0, 0x1401, 0x21) + struct.pack("<HBB", sessidx & 0xffff, 0, 0)
    return encode(hdr + bytes(body))

def parse_type3(msg):
    if len(msg) >= 0x10 and struct.unpack_from("<H", msg, 0)[0] == 3:
        dlen = struct.unpack_from("<I", msg, 8)[0]
        iotype = struct.unpack_from("<I", msg, 0xc)[0]
        return iotype, msg[0x10:0x10 + dlen]
    return None

def decode_devinfo(data):
    if len(data) < 16: return f"raw={data.hex()}"
    ch, free, total, ver = struct.unpack_from("<IIII", data, 0)
    model = data[16:32].split(b"\x00", 1)[0].decode("latin1", "replace")
    vendor = data[40:56].split(b"\x00", 1)[0].decode("latin1", "replace") if len(data) >= 56 else "?"
    return f"model={model!r} vendor={vendor!r} version=0x{ver:08x} sd_free={free} sd_total={total}"

def main():
    infos = discover(UID, targets=[BC, CAM], timeout=15.0)
    if not infos: raise SystemExit("camera not found (free it: disable HA integration)")
    pw = (infos[0].credential or cfg.VIEW_PW).encode()
    conv = int.from_bytes(os.urandom(4), "little"); conv_le = conv.to_bytes(4, "little")
    print(f"conv=0x{conv:08x}")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("", 0)); s.settimeout(0.2)
    myport = s.getsockname()[1]

    lsr = build_lanstreamreq(UID, conv=conv, password=pw, client_ip=ME, client_port=myport)
    sport = None; rsp = None
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
    if not sport: raise SystemExit("no 0x1308 lanstreamrsp")
    index = rsp[0x47]; print(f"session port={sport} index={index}")

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
        if avidx is None: avidx = struct.unpack_from("<H", dd, 0xc)[0]; print(f"video up avidx={avidx}")
        rcv.input(dd[16:16 + struct.unpack_from('<H', dd, 4)[0]]); rcv.messages()
        ak = rcv.ack_segments()
        for i in range(0, len(ak), 8): s.sendto(build(0x1409, b"".join(ak[i:i+8]), aux=0x21), (CAM, sport))
    if avidx is None: avidx = 0

    # knock PASS
    ok = None
    for _ in range(4): s.sendto(encode(cfg.build_knock(os.urandom(4), conv_le, 0x00, index)), (CAM, sport)); time.sleep(0.1)
    t = time.monotonic() + 1.2
    while time.monotonic() < t:
        try: d, _ = s.recvfrom(65535)
        except socket.timeout: continue
        try: dd = decode(d)
        except Exception: continue
        if dd[:4] == MAGIC and mt(dd) == 0x130c: ok = status_of(dd)
    print(f"knock 0x130c={ok} ({'PASS' if ok=='0000' else 'FAIL'})")
    if ok != "0000": s.close(); return

    # CONFIRM (0x130d) — complete the 2-step handshake
    for _ in range(4): s.sendto(encode(cfg.build_confirm(os.urandom(4), conv_le, 0x00, index)), (CAM, sport)); time.sleep(0.08)
    print("sent 0x130d confirm x4 (slot[0x19] should now be 'established')")

    # ioctrl over BOTH transports + full logging
    snd = KcpSender(conv)
    def kcp_ioctrl(iotype, data, tag):
        seg = snd.push(build_ioctrl_frame(avidx, iotype, data), una=rcv.rcv_nxt, ts=ms())
        s.sendto(build(0x1409, seg, aux=0x21), (CAM, sport)); print(f"  ->KCP  sn={snd.snd_nxt-1} {tag} io={iotype}")
    seqbox = [0]
    def raw_send(iotype, data, tag):
        s.sendto(raw_ioctrl(iotype, data, index, seqbox[0]), (CAM, sport)); seqbox[0]+=1
        print(f"  ->RAW  {tag} io={iotype}")

    sched = [
        (0.3, lambda: kcp_ioctrl(DEVINFO_REQ, b"\x00\x00\x00\x00", "DEVINFO")),
        (0.6, lambda: raw_send(DEVINFO_REQ, b"\x00\x00\x00\x00", "DEVINFO")),
        (2.0, lambda: kcp_ioctrl(PTZ_REQ, bytes([0,PTZ_LEFT,0,0,0,8,0,0]), "PTZ_LEFT")),
        (4.0, lambda: kcp_ioctrl(PTZ_REQ, bytes([0,PTZ_STOP,0,0,0,0,0,0]), "PTZ_STOP")),
        (5.5, lambda: kcp_ioctrl(PTZ_REQ, bytes([0,PTZ_RIGHT,0,0,0,8,0,0]), "PTZ_RIGHT")),
        (7.5, lambda: kcp_ioctrl(PTZ_REQ, bytes([0,PTZ_STOP,0,0,0,0,0,0]), "PTZ_STOP")),
    ]
    t0 = time.monotonic(); fired = [False]*len(sched)
    seen_types = {}; acked = set(); resps = []; raw1402 = 0; small_msgs = []
    la = lr = 0
    while time.monotonic() < t0 + 11:
        now = time.monotonic()
        for i,(at,fn) in enumerate(sched):
            if not fired[i] and now-t0>=at: fired[i]=True; fn()
        if now-la>0.6: s.sendto(build_alive(conv),(CAM,sport)); la=now
        if now-lr>0.4:
            for seg in snd.retransmit_segments(): s.sendto(build(0x1409,seg,aux=0x21),(CAM,sport))
            lr=now
        try: d,_=s.recvfrom(65535)
        except socket.timeout: continue
        try: dd=decode(d)
        except Exception: continue
        if dd[:4]!=MAGIC: continue
        m=mt(dd); seen_types[m]=seen_types.get(m,0)+1
        if m==0x1402: raw1402+=1; print(f"  <-RAW 0x1402: {dd[16:16+28].hex()}")
        if m in (0x140A,0x1409):
            body=dd[16:16+struct.unpack_from('<H',dd,4)[0]]
            na=snd.note_acks(body)
            if na: acked.update(na); print(f"  <-KCP-ACK our sn {na} [transport ok]")
            rcv.input(body)
            for msg in rcv.messages():
                t3=parse_type3(msg)
                if t3:
                    io,data=t3; resps.append((io,data))
                    ex="  "+decode_devinfo(data) if io==DEVINFO_RESP else ""
                    print(f"  <-IOCTRL-RESP io={io}(0x{io:x}) dlen={len(data)}{ex}")
                elif len(msg)<128:
                    small_msgs.append(msg); print(f"  <-KCP small msg ({len(msg)}B): {msg.hex()}")
            ak=rcv.ack_segments()
            for i in range(0,len(ak),8): s.sendto(build(0x1409,b"".join(ak[i:i+8]),aux=0x21),(CAM,sport))

    print("\n===== SUMMARY =====")
    print("all msgtypes seen:", {hex(k):v for k,v in sorted(seen_types.items())})
    print(f"KCP transport acked: {sorted(acked) or 'NONE'}")
    print(f"ioctrl responses: {[(hex(i),len(d)) for i,d in resps]}  raw-0x1402: {raw1402}  other-small-kcp: {len(small_msgs)}")
    if any(i==DEVINFO_RESP for i,_ in resps): print(">>> IOCTRL CHANNEL CONFIRMED (DEVINFO_RESP)")
    elif resps or raw1402 or small_msgs: print(">>> got SOME control response — inspect above")
    elif acked: print(">>> transport ok, still no app response even after confirm")
    else: print(">>> no acks")
    print("Watch: did the camera move on PTZ_LEFT/RIGHT?")
    s.close()

main()
