#!/usr/bin/env python3
"""Does PTZ travel scale with how long we hold the direction before STOP?

For each hold duration: grab a frame, pan LEFT for D, STOP, settle, grab a frame,
then pan RIGHT for D to return. Travel is measured as the horizontal pixel shift
between the two frames (column-brightness profile cross-correlation), which gives
a real displacement number rather than a vague "it changed" score.

  scales with D      -> STOP works; distance is duration-controlled (tune timing)
  identical for all D -> camera moves a FIXED step per command; duration is
                         meaningless and the whole control model needs rethinking

Camera can stay in use (it handles concurrent sessions). Read-mostly: pans + video.
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
from PIL import Image

CAM, ME, BC, UID = cfg.CAMERA_IP, cfg.CLIENT_IP, cfg.BROADCAST, cfg.UID
PTZ_REQ = 4097
LEFT, RIGHT, STOP = 6, 3, 0
DURATIONS = [0.1, 0.5, 2.0]
OUT = "/Users/cbrinkman/.claude/jobs/0eb50487/tmp"
FF = shutil.which("ffmpeg") or "/usr/local/bin/ffmpeg"

def mt(d): return struct.unpack_from("<H", d, 8)[0]
def stt(dd): return dd[36:38].hex() if len(dd) >= 38 else "??"
def ms(): return int(time.monotonic() * 1000) & 0xffffffff
def ptz(c, sp=8): return bytes([0, 0, 0, 0, 0, c & 0xff, sp & 0xff, 0, 0, 0, 1, 0])


def col_profile(path):
    im = Image.open(path).convert("L")
    w, h = im.size
    im = im.crop((0, h // 4, w, h * 3 // 4))          # middle band, less sky/ground
    w, h = im.size
    px = im.load()
    return [sum(px[x, y] for y in range(0, h, 4)) / (h / 4) for x in range(w)], w


def h_shift(p_a, p_b, w):
    """Best horizontal shift (pixels) aligning profile B onto A. +ve = scene moved right."""
    best = (None, 1e18)
    for s in range(-w // 2, w // 2, 2):
        tot = n = 0
        for x in range(0, w, 2):
            xb = x + s
            if 0 <= xb < w:
                tot += abs(p_a[x] - p_b[xb]); n += 1
        if n > w // 8:
            err = tot / n
            if err < best[1]:
                best = (s, err)
    return best


def main():
    infos = discover(UID, targets=[BC, CAM], timeout=15.0)
    if not infos: raise SystemExit("camera not found")
    pw = (infos[0].credential or cfg.VIEW_PW).encode()
    conv = int.from_bytes(os.urandom(4), "little"); conv_le = conv.to_bytes(4, "little")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("", 0)); s.settimeout(0.15)
    lsr = build_lanstreamreq(UID, conv=conv, password=pw, client_ip=ME,
                             client_port=s.getsockname()[1])
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
    index = rsp[0x47]
    rcv = KcpReceiver(conv); snd = KcpSender(conv); avidx = 0

    def pump(seconds, collect=None, direction=None):
        """Run the session for N seconds; optionally collect video / hold a direction."""
        buf = bytearray(); started = False
        end = time.monotonic() + seconds; la = lr = lc = 0
        while time.monotonic() < end:
            now = time.monotonic()
            if direction is not None and now - lc > 0.3:
                seg = snd.push(build_ioctrl_frame(avidx, PTZ_REQ, ptz(direction)),
                               una=rcv.rcv_nxt, ts=ms())
                s.sendto(build(0x1409, seg, aux=0x21), (CAM, sport)); lc = now
            if now - la > 0.6: s.sendto(build_alive(conv), (CAM, sport)); la = now
            if now - lr > 0.4:
                for sg in snd.retransmit_segments(): s.sendto(build(0x1409, sg, aux=0x21), (CAM, sport))
                lr = now
            try: d, _ = s.recvfrom(65535)
            except socket.timeout: continue
            try: dd = decode(d)
            except Exception: continue
            if dd[:4] != MAGIC or mt(dd) not in (0x140A, 0x1409): continue
            body = dd[16:16 + struct.unpack_from('<H', dd, 4)[0]]
            snd.note_acks(body); rcv.input(body)
            for msg in rcv.messages():
                fr = extract_h264(msg)
                if not fr or collect is None: continue
                if not started:
                    if not _has_sps(fr): continue
                    started = True
                buf += fr
            ak = rcv.ack_segments()
            for i in range(0, len(ak), 8):
                s.sendto(build(0x1409, b"".join(ak[i:i+8]), aux=0x21), (CAM, sport))
        return bytes(buf)

    def send_once(c):
        seg = snd.push(build_ioctrl_frame(avidx, PTZ_REQ, ptz(c)), una=rcv.rcv_nxt, ts=ms())
        s.sendto(build(0x1409, seg, aux=0x21), (CAM, sport))

    def snap(tag):
        raw = pump(2.2, collect=True)
        p_h, p_j = f"{OUT}/scale_{tag}.h264", f"{OUT}/scale_{tag}.jpg"
        open(p_h, "wb").write(raw)
        subprocess.run([FF, "-y", "-loglevel", "error", "-f", "h264", "-i", p_h,
                        "-frames:v", "1", p_j], capture_output=True)
        return p_j if os.path.exists(p_j) and os.path.getsize(p_j) else None

    pump(2.0)  # let video start
    ok = None
    for _ in range(4):
        s.sendto(encode(cfg.build_knock(os.urandom(4), conv_le, 0x00, index)), (CAM, sport)); time.sleep(0.1)
    t = time.monotonic() + 1.2
    while time.monotonic() < t:
        try: d, _ = s.recvfrom(65535)
        except socket.timeout: continue
        try: dd = decode(d)
        except Exception: continue
        if dd[:4] == MAGIC and mt(dd) == 0x130c: ok = stt(dd)
    if ok != "0000": raise SystemExit(f"knock failed ({ok})")
    for _ in range(4):
        s.sendto(encode(cfg.build_confirm(os.urandom(4), conv_le, 0x00, index)),
                 (CAM, sport)); time.sleep(0.08)
    print(f"session ready (index={index})\n")

    results = []
    for D in DURATIONS:
        a = snap(f"a{D}")
        send_once(LEFT); pump(D); send_once(STOP)   # exactly the HA behaviour
        pump(1.8)                                    # settle
        b = snap(f"b{D}")
        shift = None
        if a and b:
            pa, w = col_profile(a); pb, _ = col_profile(b)
            shift, err = h_shift(pa, pb, w)
        print(f"  hold {D:4.1f}s -> horizontal shift {shift} px" if shift is not None
              else f"  hold {D:4.1f}s -> (frame decode failed)")
        results.append((D, shift))
        send_once(RIGHT); pump(D); send_once(STOP); pump(1.8)  # return

    s.close()
    print("\n=== RESULT ===")
    for D, sh in results:
        print(f"  {D:4.1f}s : {sh} px")
    vals = [abs(sh) for _, sh in results if sh is not None]
    if len(vals) >= 2:
        if max(vals) and min(vals) / max(vals) > 0.7:
            print("\n  ~CONSTANT travel -> camera moves a FIXED step per command;")
            print("  hold duration is NOT what controls distance.")
        else:
            print("\n  travel SCALES with hold time -> duration control works;")
            print("  over-travel is a STOP latency/delivery problem.")


main()
