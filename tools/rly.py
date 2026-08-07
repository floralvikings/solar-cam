"""Option B: establish the session via 0x1105 (rlystreamreq) instead of 0x1307.

handle_rlystreamreq reports status=1 to the vendor app; handle_lanstreamreq
reports status=3. That status is very likely what gates full ioctrl. Build a
0x1105 with our own LAN address + the UID/credential we already have, send it
straight to the camera, and see if we get 0x1106 + a privileged session.
"""
import os, sys, time, struct, socket
sys.path.insert(0, "tools")
import p4p_probe_config as cfg
from p4p.lansearch import discover, LAN_SEARCH_PORT
from p4p.session import build_alive
from p4p.packet import MAGIC, build
from p4p.crypto import decode, encode
from p4p.kcp import KcpReceiver
from p4p_ext import KcpSender, build_ioctrl_frame

CAM, ME, BC, UID = cfg.CAMERA_IP, cfg.CLIENT_IP, cfg.BROADCAST, cfg.UID
def mt(d): return struct.unpack_from("<H", d, 8)[0]
def ms(): return int(time.monotonic()*1000) & 0xffffffff
def ip4(a): return bytes(int(x) for x in a.split("."))

def build_1105(my_ip, my_port, cam_port, cred, rid, conv, index=0, ctr=0):
    b = bytearray(0x6c)
    b[0] = 1; b[3] = ctr & 0xff
    struct.pack_into(">H", b, 4, my_port & 0xffff)      # peer port
    struct.pack_into(">H", b, 6, cam_port & 0xffff)     # camera port
    b[8:12]  = ip4(my_ip)                               # peer IP (us)
    b[12:16] = bytes.fromhex("c0000008")                # constant in every sample
    b[16:20] = bytes.fromhex("d40b0000")                # unknown, copied
    b[20:24] = ip4(my_ip)                               # camera's "public" IP -> us on LAN
    b[24:44] = UID.encode().ljust(20, b"\0")[:20]
    b[44:60] = cred.ljust(16, b"\0")[:16]               # view password
    b[66] = 0x0b; b[67] = index & 0xff                  # marker + session index
    b[68:72] = rid
    struct.pack_into("<I", b, 72, conv)
    b[76:81] = b"admin"
    return build(0x1105, bytes(b), aux=0x41)

infos = discover(UID, targets=[BC, CAM], timeout=15.0)
if not infos: raise SystemExit("camera not found")
cred = (infos[0].credential or cfg.VIEW_PW).encode()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("", 0)); s.settimeout(0.2)
my_port = s.getsockname()[1]
rid = os.urandom(4); conv = int.from_bytes(os.urandom(4), "little")
pkt = build_1105(ME, my_port, LAN_SEARCH_PORT, cred, rid, conv)
print(f"sending 0x1105 rlystreamreq  (me={ME}:{my_port} conv=0x{conv:08x})")
got = {}
for attempt in range(6):
    s.sendto(pkt, (CAM, LAN_SEARCH_PORT))
    t = time.monotonic() + 1.0
    while time.monotonic() < t:
        try: d, a = s.recvfrom(65535)
        except socket.timeout: continue
        if d == pkt: continue
        try: dd = decode(d)
        except Exception: continue
        if dd[:4] != MAGIC: continue
        m = mt(dd)
        got.setdefault(m, (a, dd))
        print(f"   <- 0x{m:04x} from {a[0]}:{a[1]} ({len(dd)}B)")
    if 0x1106 in got or 0x130e in got: break
if not got:
    print("\n>>> no reply to 0x1105")
else:
    print(f"\nreplies: {[hex(k) for k in got]}")
    for m,(a,dd) in got.items():
        body = dd[16:16+struct.unpack_from('<H',dd,4)[0]]
        print(f"  0x{m:04x} body[:64]: {body[:64].hex()}")
s.close()
