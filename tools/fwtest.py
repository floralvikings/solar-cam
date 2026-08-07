"""SAFE probe: ask the camera to fetch firmware from us, but serve 404.

Sends IOTYPE_USER_IPCAM_FIRMWARE_UPDATE_REQ (4631) with a URL pointing at a local
HTTP server. The server LOGS the request and returns 404, so the download always
fails and the camera can never reach the flashcp step. If we see a request, the
whole network-flash path is proven.
"""
import os, sys, time, struct, socket, threading, hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
sys.path.insert(0, "tools")
import p4p_probe_config as cfg
from p4p.lansearch import discover, LAN_SEARCH_PORT
from p4p.session import build_lanstreamreq, parse_lanstreamrsp, build_alive
from p4p.packet import MAGIC, build
from p4p.crypto import decode, encode
from p4p.kcp import KcpReceiver
from p4p_ext import KcpSender, build_ioctrl_frame

CAM, ME, BC, UID = cfg.CAMERA_IP, cfg.CLIENT_IP, cfg.BROADCAST, cfg.UID
PORT = 8080
PATH = "/fw-probe.bin"
FW_UPDATE_REQ = 4631
HITS = []

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        HITS.append((time.strftime("%H:%M:%S"), self.client_address[0], "GET", self.path,
                     self.headers.get("User-Agent", "")))
        self.send_response(404); self.end_headers()
    def do_HEAD(self):
        HITS.append((time.strftime("%H:%M:%S"), self.client_address[0], "HEAD", self.path,
                     self.headers.get("User-Agent", "")))
        self.send_response(404); self.end_headers()
    def log_message(self, *a): pass

srv = HTTPServer(("0.0.0.0", PORT), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
url = f"http://{ME}:{PORT}{PATH}"
print(f"HTTP probe server on 0.0.0.0:{PORT} (always 404)\nURL offered to camera: {url}\n")

def fw_payload(url: str, size: int = 1024, version: int = 0x7FFFFFFF, ftype: int = 0) -> bytes:
    md5 = hashlib.md5(b"deliberately-wrong").hexdigest().encode()   # 32 ASCII hex
    d = bytearray(172)
    struct.pack_into("<I", d, 0, version)
    d[4] = ftype; d[5] = len(url); d[6] = len(md5); d[7] = 0
    struct.pack_into("<I", d, 8, size)
    d[12:12+len(md5)] = md5
    d[44:44+len(url)] = url.encode()
    return bytes(d)

def mt(x): return struct.unpack_from("<H", x, 8)[0]
def stt(x): return x[36:38].hex() if len(x) >= 38 else "??"
def ms(): return int(time.monotonic()*1000) & 0xffffffff

infos = discover(UID, targets=[BC, CAM], timeout=15.0)
if not infos: raise SystemExit("camera not found")
pw = (infos[0].credential or cfg.VIEW_PW).encode()
conv = int.from_bytes(os.urandom(4), "little"); cl = conv.to_bytes(4, "little")
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("", 0)); s.settimeout(0.1)
lsr = build_lanstreamreq(UID, conv=conv, password=pw, client_ip=ME, client_port=s.getsockname()[1])
sport = rsp = None
for _ in range(6): s.sendto(lsr, (CAM, LAN_SEARCH_PORT)); time.sleep(0.1)
t = time.monotonic()+3
while time.monotonic() < t and rsp is None:
    try: d,_ = s.recvfrom(65535)
    except socket.timeout: break
    if d == lsr: continue
    try:
        dd = decode(d)
        if dd[:4]==MAGIC and mt(dd)==0x1308: rsp=dd; sport=parse_lanstreamrsp(dd).session_port
    except Exception: pass
if not sport: raise SystemExit("no 0x1308 (camera busy?)")
idx = rsp[0x47]; rcv = KcpReceiver(conv); snd = KcpSender(conv)
seen=[]
def pump(sec):
    end=time.monotonic()+sec; la=lr=0
    while time.monotonic()<end:
        now=time.monotonic()
        if now-la>0.6: s.sendto(build_alive(conv),(CAM,sport)); la=now
        if now-lr>0.15:
            for sg in snd.retransmit_segments(): s.sendto(build(0x1409,sg,aux=0x21),(CAM,sport))
            lr=now
        try: d,_=s.recvfrom(65535)
        except socket.timeout: continue
        try: dd=decode(d)
        except Exception: continue
        if dd[:4]!=MAGIC: continue
        if mt(dd)==0x1402: seen.append(('raw1402',dd[16:16+40].hex()))
        if mt(dd) in (0x1409,0x140A):
            b=dd[16:16+struct.unpack_from('<H',dd,4)[0]]; snd.note_acks(b); rcv.input(b); rcv.messages()
            ak=rcv.ack_segments()
            for i in range(0,len(ak),8): s.sendto(build(0x1409,b"".join(ak[i:i+8]),aux=0x21),(CAM,sport))
pump(2.0)
ok=None
for _ in range(4): s.sendto(encode(cfg.build_knock(os.urandom(4),cl,0x00,idx)),(CAM,sport)); time.sleep(0.1)
t=time.monotonic()+1.5
while time.monotonic()<t:
    try: d,_=s.recvfrom(65535)
    except socket.timeout: continue
    try: dd=decode(d)
    except Exception: continue
    if dd[:4]==MAGIC and mt(dd)==0x130c: ok=stt(dd)
for _ in range(4): s.sendto(encode(cfg.build_confirm(os.urandom(4),cl,0x00,idx)),(CAM,sport)); time.sleep(0.08)
print(f"session ready (index={idx}, knock={ok})")
VARIANTS = [
    (0, 0x7FFFFFFF, "ftype=0 ver=max"),
    (1, 0x7FFFFFFF, "ftype=1 ver=max"),
    (2, 0x7FFFFFFF, "ftype=2 ver=max"),
    (0, 0,          "ftype=0 ver=0"),
    (1, 99999,      "ftype=1 ver=99999"),
]
# also try a CHECK (4629) first, some firmwares require it
seg = snd.push(build_ioctrl_frame(0, 4629, b"\x00"*8), una=rcv.rcv_nxt, ts=ms())
s.sendto(build(0x1409, seg, aux=0x21), (CAM, sport)); print("-> sent 4629 UPDATE_CHECK"); pump(4.0)
for ftype, ver, tag in VARIANTS:
    payload = fw_payload(url, version=ver, ftype=ftype)
    seg = snd.push(build_ioctrl_frame(0, FW_UPDATE_REQ, payload), una=rcv.rcv_nxt, ts=ms())
    s.sendto(build(0x1409, seg, aux=0x21), (CAM, sport))
    print(f"-> 4631 {tag}"); pump(12.0)
    if HITS: print("   !!! FETCH SEEN"); break
pump(15.0)
s.close(); srv.shutdown()
print(f"HTTP requests received: {len(HITS)}")
for h in HITS: print("   ", h)
print(f"P4P responses: {seen if seen else 'none'}")
print("\n>>> CAMERA FETCHED — network flashing is viable!" if HITS else
      "\n>>> no fetch; camera ignored the update command on this session")
