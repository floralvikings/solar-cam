#!/usr/bin/env python3
"""Resolve the device-assigned session index offset in the 0x1308 response.

Dumps the response, shows resp[0x46]/[0x47], then sweeps the knock chanidx to
find which value actually passes (status 0000). Earlier tests only ever saw
index 0 (where 0x46==0x47==0), hiding a possible off-by-one. Camera FREE.
"""
import os, sys, time, struct, socket
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p4p_probe_config as cfg
from p4p.lansearch import discover, LAN_SEARCH_PORT
from p4p.session import build_lanstreamreq, parse_lanstreamrsp, build_alive
from p4p.packet import MAGIC, build
from p4p.crypto import decode, encode
from p4p.kcp import KcpReceiver

CAM, ME, BC, UID = cfg.CAMERA_IP, cfg.CLIENT_IP, cfg.BROADCAST, cfg.UID
def mt(d): return struct.unpack_from("<H", d, 8)[0]
def stt(dd): return dd[36:38].hex() if len(dd) >= 38 else "??"

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("", 0)); s.settimeout(0.2)
    myport = s.getsockname()[1]
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
    if not sport: raise SystemExit("no 0x1308 (camera busy?)")
    print(f"0x1308 full ({len(rsp)}B): {rsp.hex()}")
    print(f"resp[0x44:0x4c] = {rsp[0x44:0x4c].hex()}   resp[0x46]={rsp[0x46]}  resp[0x47]={rsp[0x47]}")

    # bring video up (keeps the slot alive)
    rcv = KcpReceiver(conv)
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
        rcv.input(dd[16:16+struct.unpack_from('<H', dd, 4)[0]]); rcv.messages()
        ak = rcv.ack_segments()
        for i in range(0, len(ak), 8): s.sendto(build(0x1409, b"".join(ak[i:i+8]), aux=0x21), (CAM, sport))

    # sweep chanidx to find the one that passes
    print("\nsweeping knock chanidx (looking for status != ffff):")
    winners = []
    for idx in [rsp[0x46], rsp[0x47]] + list(range(0, 16)):
        got = None
        for _ in range(4): s.sendto(encode(cfg.build_knock(os.urandom(4), conv_le, 0x00, idx)), (CAM, sport)); time.sleep(0.08)
        t = time.monotonic()+1.0
        while time.monotonic() < t:
            try: d, _ = s.recvfrom(65535)
            except socket.timeout: continue
            try: dd = decode(d)
            except Exception: continue
            if dd[:4] == MAGIC and mt(dd) == 0x130c: got = stt(dd)
        tag = "PASS" if (got and got != "ffff") else ""
        print(f"  chanidx={idx:3} -> {got} {tag}")
        if tag: winners.append(idx)
    print(f"\nresp[0x46]={rsp[0x46]} resp[0x47]={rsp[0x47]} ; passing chanidx: {sorted(set(winners))}")
    s.close()

main()
