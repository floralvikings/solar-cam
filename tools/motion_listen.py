"""Hold a local session open and log EVERY non-media frame, hunting for pushes
(EVENT_REPORT 8191 / PIR / motion). Pushes may work even though request/response
doesn't, since the camera initiates them."""
import os, sys, time, struct, socket, collections
sys.path.insert(0, "tools")
import p4p_probe_config as cfg
from p4p.lansearch import discover, LAN_SEARCH_PORT
from p4p.session import build_lanstreamreq, parse_lanstreamrsp, build_alive
from p4p.packet import MAGIC, build
from p4p.crypto import decode, encode
from p4p.kcp import KcpReceiver
from p4p_ext import KcpSender
HDR=struct.Struct('<IBBHIIII')
CAM,ME,BC,UID=cfg.CAMERA_IP,cfg.CLIENT_IP,cfg.BROADCAST,cfg.UID
DURATION=float(sys.argv[1]) if len(sys.argv)>1 else 90.0
NAMES={8191:'EVENT_REPORT',4675:'GETPIR',793:'LISTEVENT_RESP',961:'ADVSETTINGS_RESP',
       47:'NIGHTLIGHT_RESP',4096:'PTZ_RESP',817:'DEVINFO_RESP',8463:'PTZ_INFO_EVENT'}
def mt(d): return struct.unpack_from("<H",d,8)[0]
def stt(d): return d[36:38].hex() if len(d)>=38 else "??"

infos=discover(UID,targets=[BC,CAM],timeout=15.0)
if not infos: raise SystemExit("camera not found")
pw=(infos[0].credential or cfg.VIEW_PW).encode()
conv=int.from_bytes(os.urandom(4),"little"); cl=conv.to_bytes(4,"little")
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("",0)); s.settimeout(0.1)
lsr=build_lanstreamreq(UID,conv=conv,password=pw,client_ip=ME,client_port=s.getsockname()[1])
sport=rsp=None
for _ in range(6): s.sendto(lsr,(CAM,LAN_SEARCH_PORT)); time.sleep(0.1)
t=time.monotonic()+3
while time.monotonic()<t and rsp is None:
    try: d,_=s.recvfrom(65535)
    except socket.timeout: break
    if d==lsr: continue
    try:
        dd=decode(d)
        if dd[:4]==MAGIC and mt(dd)==0x1308: rsp=dd; sport=parse_lanstreamrsp(dd).session_port
    except Exception: pass
if not sport: raise SystemExit("no 0x1308 (camera busy?)")
idx=rsp[0x47]; rcv=KcpReceiver(conv); snd=KcpSender(conv)
seen=collections.Counter(); events=[]
t0=time.monotonic()
def handle(dd):
    m=mt(dd); seen[m]+=1
    if m==0x1402:
        events.append((time.monotonic()-t0,'RAW-0x1402',0,dd[16:16+40].hex())); return
    if m not in (0x1409,0x140A): return
    b=dd[16:16+struct.unpack_from('<H',dd,4)[0]]
    snd.note_acks(b)
    off=0
    while len(b)-off>=HDR.size:
        c,cmd,frg,wnd,ts,sn,una,ln=HDR.unpack_from(b,off)
        if c!=conv: break
        pl=b[off+HDR.size:off+HDR.size+ln]; off+=HDR.size+ln
        if cmd!=81 or len(pl)<0x10: continue
        lead=struct.unpack_from('<I',pl,0)[0]
        if lead in (0x11,0x13): continue          # video / audio
        iot=struct.unpack_from('<I',pl,0xc)[0]; dl=struct.unpack_from('<I',pl,8)[0]
        if dl>1024: continue
        events.append((time.monotonic()-t0,f'type={lead}',iot,pl[0x10:0x10+min(dl,48)].hex()))
    rcv.input(b)
    ak=rcv.ack_segments()
    for i in range(0,len(ak),8): s.sendto(build(0x1409,b"".join(ak[i:i+8]),aux=0x21),(CAM,sport))
def pump(sec):
    end=time.monotonic()+sec; la=0
    while time.monotonic()<end:
        now=time.monotonic()
        if now-la>0.6: s.sendto(build_alive(conv),(CAM,sport)); la=now
        try: d,_=s.recvfrom(65535)
        except socket.timeout: continue
        try: dd=decode(d)
        except Exception: continue
        if dd[:4]==MAGIC: handle(dd)
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
print(f"session ready (index={idx}, knock={ok}) — LISTENING {DURATION:.0f}s", flush=True)
print("### WALK IN FRONT OF THE CAMERA A FEW TIMES NOW ###", flush=True)
events.clear(); t0=time.monotonic()
pump(DURATION)
s.close()
print(f"\nmsgtypes seen: {dict((hex(k),v) for k,v in seen.items())}")
print(f"non-media frames captured: {len(events)}")
for t,kind,iot,hx in events[:40]:
    print(f"   t={t:6.1f}s {kind:12} io={iot:6} {NAMES.get(iot,''):18} {hx}")
if not events:
    print("   (nothing — no unsolicited pushes on this session)")
