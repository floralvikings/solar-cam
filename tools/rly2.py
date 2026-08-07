"""Full relay-path session: 0x1105 -> 0x1106 -> knock/confirm -> QUERY.
If 961 comes back, status=1 sessions get full ioctrl and Option B is proven."""
import os, sys, time, struct, socket
sys.path.insert(0, "tools")
import p4p_probe_config as cfg
from p4p.lansearch import discover, LAN_SEARCH_PORT
from p4p.session import build_alive
from p4p.packet import MAGIC, build
from p4p.crypto import decode, encode
from p4p.kcp import KcpReceiver
from p4p_ext import KcpSender, build_ioctrl_frame
HDR=struct.Struct('<IBBHIIII')
CAM,ME,BC,UID=cfg.CAMERA_IP,cfg.CLIENT_IP,cfg.BROADCAST,cfg.UID
def mt(d): return struct.unpack_from("<H",d,8)[0]
def stt(d): return d[36:38].hex() if len(d)>=38 else "??"
def ms(): return int(time.monotonic()*1000)&0xffffffff
def ip4(a): return bytes(int(x) for x in a.split("."))

def build_1105(my_ip,my_port,cam_port,cred,rid,conv,index=0,ctr=0):
    b=bytearray(0x6c); b[0]=1; b[3]=ctr&0xff
    struct.pack_into(">H",b,4,my_port&0xffff); struct.pack_into(">H",b,6,cam_port&0xffff)
    b[8:12]=ip4(my_ip); b[12:16]=bytes.fromhex("c0000008"); b[16:20]=bytes.fromhex("d40b0000")
    b[20:24]=ip4(my_ip); b[24:44]=UID.encode().ljust(20,b"\0")[:20]
    b[44:60]=cred.ljust(16,b"\0")[:16]; b[66]=0x0b; b[67]=index&0xff
    b[68:72]=rid; struct.pack_into("<I",b,72,conv); b[76:81]=b"admin"
    return build(0x1105,bytes(b),aux=0x41)

infos=discover(UID,targets=[BC,CAM],timeout=15.0)
cred=(infos[0].credential or cfg.VIEW_PW).encode()
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("",0)); s.settimeout(0.15)
my_port=s.getsockname()[1]; rid=os.urandom(4); conv=int.from_bytes(os.urandom(4),"little")
cl=conv.to_bytes(4,"little")
pkt=build_1105(ME,my_port,LAN_SEARCH_PORT,cred,rid,conv)
sport=None; idx=0
for _ in range(6):
    s.sendto(pkt,(CAM,LAN_SEARCH_PORT))
    t=time.monotonic()+1.0
    while time.monotonic()<t:
        try: d,a=s.recvfrom(65535)
        except socket.timeout: continue
        if d==pkt: continue
        try: dd=decode(d)
        except Exception: continue
        if dd[:4]!=MAGIC: continue
        if mt(dd)==0x1106:
            sport=a[1]; body=dd[16:16+struct.unpack_from('<H',dd,4)[0]]
            idx=body[0x35] if len(body)>0x35 else 0
        elif sport is None and mt(dd)==0x1406: sport=a[1]
    if sport: break
if not sport: raise SystemExit("no 0x1106 — relay session not created")
print(f"relay session up: port={sport} index={idx} conv=0x{conv:08x}")
rcv=KcpReceiver(conv); snd=KcpSender(conv); resp=[]
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
        m=mt(dd)
        if m==0x1402: resp.append(('raw1402',0,dd[16:16+48].hex()))
        if m not in (0x1409,0x140A): continue
        b=dd[16:16+struct.unpack_from('<H',dd,4)[0]]; snd.note_acks(b)
        off=0
        while len(b)-off>=HDR.size:
            c,cmd,frg,wnd,ts,sn,una,ln=HDR.unpack_from(b,off)
            if c!=conv: break
            pl=b[off+HDR.size:off+HDR.size+ln]; off+=HDR.size+ln
            if cmd!=81 or len(pl)<0x10: continue
            lead=struct.unpack_from('<I',pl,0)[0]
            if lead in (0x11,0x13): continue
            iot=struct.unpack_from('<I',pl,0xc)[0]; dl=struct.unpack_from('<I',pl,8)[0]
            if dl<=1024: resp.append((f'type{lead}',iot,pl[0x10:0x10+min(dl,64)].hex()))
        rcv.input(b); ak=rcv.ack_segments()
        for i in range(0,len(ak),8): s.sendto(build(0x1409,b"".join(ak[i:i+8]),aux=0x21),(CAM,sport))
pump(2.5)
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
print(f"knock={ok}")
resp.clear()
for iot,name in ((960,"GET_ADVANCESETTINGS"),(816,"DEVINFO")):
    seg=snd.push(build_ioctrl_frame(0,iot,b"\x00\x00\x00\x00"),una=rcv.rcv_nxt,ts=ms())
    s.sendto(build(0x1409,seg,aux=0x21),(CAM,sport))
    print(f"-> query {name} ({iot})"); pump(5.0)
s.close()
print(f"\nresponses: {len(resp)}")
for k,iot,hx in resp[:6]: print(f"   {k} io={iot} {hx}")
print("\n>>> OPTION B WORKS — relay session gets full ioctrl!" if any(i in (961,817) for _,i,_ in resp)
      else "\n>>> relay session created, but still no query response")
