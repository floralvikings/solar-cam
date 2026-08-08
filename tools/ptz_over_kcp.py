#!/usr/bin/env python3
"""Send ioctrl over the KCP reliable channel, like the real UBox app does.

Builds on the SOLVED authenticated knock (knock_indexed.py): lanstreamreq ->
device-assigned index from 0x1308 resp[0x46] -> knock passes -> video up. Then it
sends ioctrl the way p4p_client_send_ioctrl @0x33c68 does: a type-3 frame over the
avchn's KCP (client->device PUSH, wrapped in obfuscated 0x1409), NOT a raw 0x1401.

Success signals (in order of certainty):
  1. Device KCP-ACKs our PUSH sn  -> the reliable channel accepted our command.
  2. DEVINFO_REQ(816) -> DEVINFO_RESP(817) comes back (type-3 frame via device
     KCP PUSH) -> the app-layer ioctrl handler ran (bonus: model/fw version).
  3. PTZ physically moves the camera (watch it).

Config from env or local/device.json. Camera FREE (HA integration off). UDP only;
PTZ is reversible (it re-centers with a STOP + opposite move). Read-mostly.
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

# ioTypes (apk/.../AVIOCTRLDEFs.java)
DEVINFO_REQ, DEVINFO_RESP = 816, 817
PTZ_REQ, PTZ_RESP = 4097, 4096
# ENUM_PTZCMD opcodes: LEFT=6 RIGHT=3 UP=1 DOWN=2 STOP=0
PTZ_LEFT, PTZ_RIGHT, PTZ_STOP = 6, 3, 0

def mt(d): return struct.unpack_from("<H", d, 8)[0]
def status_of(dd): return dd[36:38].hex() if len(dd) >= 38 else "??"
def ms(): return int(time.monotonic() * 1000) & 0xffffffff

def ptz_payload(control, *, channel=0, speed=8):
    # SMsgAVIoctrlPtzCmd.parseContent -> byte[8] {b,b2,b3,b4,b5,b6,0,0}.
    # Exact field order unconfirmed; this guess puts channel@0, control@1, speed@5.
    return bytes([channel & 0xff, control & 0xff, 0, 0, 0, speed & 0xff, 0, 0])

def parse_type3(msg):
    """If a reassembled KCP message is a type-3 ioctrl frame, return (iotype, data)."""
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

    # 1) lanstreamreq -> index + session port
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
            if dd[:4] == MAGIC and mt(dd) == 0x1308:
                rsp = dd; sport = parse_lanstreamrsp(dd).session_port
        except Exception: pass
    if not sport: raise SystemExit("no 0x1308 lanstreamrsp (busy/auth)")
    index = rsp[0x46]
    print(f"session port = {sport}  device-assigned index = {index}")

    # 2) video up -> avidx
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
        if avidx is None: avidx = struct.unpack_from("<H", dd, 0xc)[0]; print(f"video up, avidx={avidx}")
        rcv.input(dd[16:16 + struct.unpack_from('<H', dd, 4)[0]])
        rcv.messages()
        ak = rcv.ack_segments()
        for i in range(0, len(ak), 8): s.sendto(build(0x1409, b"".join(ak[i:i+8]), aux=0x21), (CAM, sport))
    if avidx is None: avidx = 0; print("  (no video; assuming avidx=0)")

    # 3) knock PASS (device-assigned index, hdr[0xf]=0)
    ok = None
    for _ in range(4): s.sendto(encode(cfg.build_knock(os.urandom(4), conv_le, 0x00, index)), (CAM, sport)); time.sleep(0.1)
    t = time.monotonic() + 1.5
    while time.monotonic() < t:
        try: d, _ = s.recvfrom(65535)
        except socket.timeout: continue
        try: dd = decode(d)
        except Exception: continue
        if dd[:4] == MAGIC and mt(dd) == 0x130c: ok = status_of(dd)
    print(f"knock -> 0x130c status={ok} ({'PASS' if ok=='0000' else 'FAIL'})")
    if ok != "0000":
        print("knock did not pass; aborting ioctrl"); s.close(); return

    # 4) ioctrl over KCP
    snd = KcpSender(conv)
    def send_ioctrl(iotype, data, tag):
        frame = build_ioctrl_frame(avidx, iotype, data)
        seg = snd.push(frame, una=rcv.rcv_nxt, ts=ms())
        s.sendto(build(0x1409, seg, aux=0x21), (CAM, sport))
        print(f"  -> ioctrl sn={snd.snd_nxt-1} {tag} iotype={iotype} dlen={len(data)}")

    # schedule: devinfo (channel proof), then PTZ left/stop/right/stop (movement)
    schedule = [
        (0.3, lambda: send_ioctrl(DEVINFO_REQ, b"\x00\x00\x00\x00", "DEVINFO_REQ")),
        (1.5, lambda: send_ioctrl(PTZ_REQ, ptz_payload(PTZ_LEFT), "PTZ_LEFT")),
        (3.5, lambda: send_ioctrl(PTZ_REQ, ptz_payload(PTZ_STOP), "PTZ_STOP")),
        (5.0, lambda: send_ioctrl(PTZ_REQ, ptz_payload(PTZ_RIGHT), "PTZ_RIGHT")),
        (7.0, lambda: send_ioctrl(PTZ_REQ, ptz_payload(PTZ_STOP), "PTZ_STOP")),
    ]
    t0 = time.monotonic(); fired = [False] * len(schedule)
    transport_acked = set(); ioctrl_resps = []; raw1402 = 0
    last_alive = last_rtx = 0
    end = t0 + 10
    while time.monotonic() < end:
        now = time.monotonic()
        for i, (at, fn) in enumerate(schedule):
            if not fired[i] and now - t0 >= at: fired[i] = True; fn()
        if now - last_alive > 0.6:
            s.sendto(build_alive(conv), (CAM, sport)); last_alive = now
        if now - last_rtx > 0.4:
            for seg in snd.retransmit_segments():
                s.sendto(build(0x1409, seg, aux=0x21), (CAM, sport))
            last_rtx = now
        try: d, _ = s.recvfrom(65535)
        except socket.timeout: continue
        try: dd = decode(d)
        except Exception: continue
        if dd[:4] != MAGIC: continue
        m = mt(dd)
        if m == 0x1402: raw1402 += 1; print(f"  <- RAW 0x1402 ack: {dd[16:16+24].hex()}")
        if m in (0x140A, 0x1409):
            body = dd[16:16 + struct.unpack_from('<H', dd, 4)[0]]
            newacks = snd.note_acks(body)
            if newacks:
                transport_acked.update(newacks); print(f"  <- device KCP-ACKed our sn {newacks}  [TRANSPORT OK]")
            rcv.input(body)
            for msg in rcv.messages():
                t3 = parse_type3(msg)
                if t3:
                    iotype, data = t3
                    ioctrl_resps.append((iotype, data))
                    extra = "  " + decode_devinfo(data) if iotype == DEVINFO_RESP else ""
                    print(f"  <- IOCTRL RESPONSE iotype={iotype} (0x{iotype:x}) dlen={len(data)}{extra}")
            ak = rcv.ack_segments()
            for i in range(0, len(ak), 8): s.sendto(build(0x1409, b"".join(ak[i:i+8]), aux=0x21), (CAM, sport))

    print("\n===== SUMMARY =====")
    print(f"knock: PASS   KCP transport acked pushes: {sorted(transport_acked)}  ({'OK' if transport_acked else 'NONE'})")
    print(f"ioctrl responses: {[(hex(i),len(d)) for i,d in ioctrl_resps]}   raw-0x1402: {raw1402}")
    if any(i == DEVINFO_RESP for i, _ in ioctrl_resps):
        print(">>> IOCTRL CHANNEL CONFIRMED (DEVINFO_RESP received)")
    elif transport_acked:
        print(">>> KCP transport works (pushes acked) but no app response yet — PTZ payload/iotype may need tuning")
    else:
        print(">>> no KCP acks — sender/transport still off")
    print("Did the camera physically move during PTZ_LEFT/RIGHT? (watch)")
    s.close()

main()
