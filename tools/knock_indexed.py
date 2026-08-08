#!/usr/bin/env python3
"""Knock into a lanstreamreq-allocated session using the DEVICE-ASSIGNED index.

Root cause of the earlier failure (knock_after_stream.py): the knock's channel
slot is selected by pkt[0x3b] = a *device-assigned* random index, not a fixed 1.
Device flow (libUBICAPIs.so):

  p4p_device_handle_lanstreamreq @0x42620:
     index = p4p_alloc_session(...)          # random, != 0xf
     slot  = gp + 0x101c + index*308
     slot[0xc]  = lanstreamreq.pkt[0x58]     # = our body[72] conv
     slot[0x17] = lanstreamreq.pkt[0x13]     # = our body[3]   (0)
     0x1308 resp carries `index` in a marker: 04 01 00 00 00 <IDX> 00 00 00 00 <convLE>

  p4p_device_handle_knock @0x44458:
     chanidx = pkt[0x3b];  slot = gp + 0x101c + chanidx*308
     require slot[0]!=0  and  slot[0xc]==pkt[0x40]  and  slot[0x17]==pkt[0xf]
     -> 0x130c status 0x0000 (PASS) else 0xffff

So: lanstreamreq(conv=C) -> read IDX from 0x1308 -> knock(pkt[0x3b]=IDX,
pkt[0x40]=C, pkt[0xf]=0). SUCCESS SIGNAL: 0x130c status != ffff, then 0x1402
acks > 0 = ioctrl accepted (controls + FILE_DOWNLOAD firmware dump unlocked).

Config from env or local/device.json. Run with the camera FREE (HA integration
disabled). Read-only: UDP only.
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

def find_indexes(resp, conv):
    """Locate the device-assigned session index in a decoded 0x1308 response.

    Primary: the marker `04 01 <b50><b51><b52> <IDX> <b54:2> <b56:2> <convLE>`;
    IDX sits 5 bytes before the conv. Also report the client-parser byte offsets
    (resp[0x46]/[0x47]) as fallbacks."""
    convb = struct.pack("<I", conv & 0xffffffff)
    cands = []
    start = 0
    while True:
        p = resp.find(convb, start)
        if p < 0: break
        m = p - 0xa                      # marker start
        if m >= 0 and resp[m:m+2] == b"\x04\x01":
            cands.append(("marker", resp[m+5], m))
        start = p + 1
    for off in (0x46, 0x47):
        if len(resp) > off:
            cands.append((f"resp[0x{off:02x}]", resp[off], off))
    # de-dup by value, keep first-seen source
    seen, out = set(), []
    for src, v, at in cands:
        if v not in seen:
            seen.add(v); out.append((src, v, at))
    return out

def main():
    infos = discover(UID, targets=[BC, CAM], timeout=15.0)
    if not infos: raise SystemExit("camera not found (free it: disable HA integration)")
    pw = (infos[0].credential or cfg.VIEW_PW).encode()
    conv = int.from_bytes(os.urandom(4), "little"); conv_le = conv.to_bytes(4, "little")
    print(f"conv=0x{conv:08x}")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("", 0)); s.settimeout(0.3)
    myport = s.getsockname()[1]

    # 1) lanstreamreq -> 0x1308 (allocates session; carries the index) + session port
    lsr = build_lanstreamreq(UID, conv=conv, password=pw, client_ip=ME, client_port=myport)
    sport = None; rsp1308 = None
    for _ in range(6): s.sendto(lsr, (CAM, LAN_SEARCH_PORT)); time.sleep(0.1)
    t = time.monotonic() + 3
    while time.monotonic() < t and rsp1308 is None:
        try: d, _ = s.recvfrom(65535)
        except socket.timeout: break
        if d == lsr: continue
        try:
            dd = decode(d)
            if dd[:4] == MAGIC and mt(dd) == 0x1308:
                rsp1308 = dd
                sport = parse_lanstreamrsp(dd).session_port
        except Exception: pass
    if not sport: raise SystemExit("no 0x1308 lanstreamrsp (busy/auth)")
    print(f"session port = {sport}")

    # 1b) locate the device-assigned index in the 0x1308
    body = rsp1308[16:16 + struct.unpack_from("<H", rsp1308, 4)[0]]
    print(f"0x1308 body ({len(body)}B): {body[:0x60].hex()}")
    cands = find_indexes(rsp1308, conv)
    if not cands:
        print("!! could not locate index marker; dumping full decoded response for analysis")
        print(rsp1308.hex())
        raise SystemExit("no index candidate found")
    print("index candidates:", ", ".join(f"{src}=0x{v:02x}({v})@{at}" for src, v, at in cands))

    # 2) start video, grab AV session index (for ioctrl addressing)
    kcp = KcpReceiver(conv); avidx = None
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
        if avidx is None: avidx = struct.unpack_from("<H", dd, 0xc)[0]; print(f"video up, AV index={avidx}")
        kcp.input(dd[16:16 + struct.unpack_from('<H', dd, 4)[0]])
        for m in kcp.messages(): extract_h264(m)
        ak = kcp.ack_segments()
        for i in range(0, len(ak), 8): s.sendto(build(0x1409, b"".join(ak[i:i+8]), aux=0x21), (CAM, sport))
    if avidx is None: print("  (no video yet; continuing to knock anyway)")

    # 3) knock with the device-assigned index; hdr[0xf]=0 (== our lanstreamreq body[3])
    passed = None
    tried = []
    for src, chanidx, _at in cands:
        for hdr0f in (0x00, 0x04):
            got = None
            for _ in range(4):
                s.sendto(encode(cfg.build_knock(os.urandom(4), conv_le, hdr0f, chanidx)), (CAM, sport))
                time.sleep(0.1)
            t = time.monotonic() + 1.2
            while time.monotonic() < t:
                try: d, _ = s.recvfrom(65535)
                except socket.timeout: continue
                try: dd = decode(d)
                except Exception: continue
                if dd[:4] == MAGIC and mt(dd) == 0x130c: got = status_of(dd)
            tried.append((src, chanidx, hdr0f, got))
            print(f"  knock idx=0x{chanidx:02x}({src}) hdr[0xf]=0x{hdr0f:02x} -> 0x130c status={got}")
            if got and got != "ffff":
                passed = (chanidx, hdr0f); print(f"  >>> STATUS FLIPPED: idx=0x{chanidx:02x} hdr[0xf]=0x{hdr0f:02x}")
                break
        if passed: break
    if passed is None:
        print(">>> knock still ffff for every index candidate; slot mapping still off")

    # 4) test ioctrl: PTZ(4097) + FILE_LIST(4864); count acks
    acks = frsp = 0
    if avidx is not None:
        ptz = bytearray(12); ptz[5] = 3; ptz[6] = 8
        seq = 0; last_a = last_p = 0; t = time.monotonic() + 5
        while time.monotonic() < t:
            now = time.monotonic()
            if now - last_a > 0.7: s.sendto(build_alive(conv), (CAM, sport)); last_a = now
            if now - last_p > 0.3:
                s.sendto(build_ioctrl(4097, bytes(ptz), avidx, seq), (CAM, sport)); seq += 1
                s.sendto(build_ioctrl(4864, bytes(12), avidx, seq), (CAM, sport)); seq += 1
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
                kcp.input(dd[16:16 + struct.unpack_from('<H', dd, 4)[0]])
                for mm in kcp.messages(): extract_h264(mm)
                ak = kcp.ack_segments()
                for i in range(0, len(ak), 8): s.sendto(build(0x1409, b"".join(ak[i:i+8]), aux=0x21), (CAM, sport))
    print(f"\nsummary: knock-passed={passed is not None} 0x1402-acks={acks} file-rsp={frsp}")
    print("acks>0 -> ioctrl accepted = controls + FILE_DOWNLOAD firmware dump unlocked")
    s.close()

main()
