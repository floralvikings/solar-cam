"""Send arbitrary ioctrl queries on our own local session and dump responses."""
import os, sys, time, struct, socket
sys.path.insert(0, "tools")
import p4p_probe_config as cfg
from p4p.lansearch import discover, LAN_SEARCH_PORT
from p4p.session import build_lanstreamreq, parse_lanstreamrsp, build_alive
from p4p.packet import MAGIC, build
from p4p.crypto import decode, encode
from p4p.kcp import KcpReceiver
from p4p_ext import KcpSender, build_ioctrl_frame
HDR=struct.Struct('<IBBHIIII')
CAM,ME,BC,UID=cfg.CAMERA_IP,cfg.CLIENT_IP,cfg.BROADCAST,cfg.UID
def mt(d): return struct.unpack_from("<H",d,8)[0]
def stt(d): return d[36:38].hex() if len(d)>=38 else "??"
def ms(): return int(time.monotonic()*1000)&0xffffffff
QUERIES=[(960,b"\x00\x00\x00\x00","GET_ADVANCESETTINGS"),(816,b"\x00\x00\x00\x00","DEVINFO")]

infos=discover(UID,targets=[BC,CAM],timeout=15.0)
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
if not sport: raise SystemExit("no 0x1308")
idx=rsp[0x47]; rcv=KcpReceiver(conv); snd=KcpSender(conv)
import collections
SEEN=collections.Counter(); RAW=[]
def pump(sec, want=None):
    out=[]; end=time.monotonic()+sec; la=lr=0
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
        SEEN[mt(dd)]+=1
        if mt(dd)==0x1402: RAW.append(dd)
        if mt(dd) not in (0x1409,0x140A): continue
        b=dd[16:16+struct.unpack_from('<H',dd,4)[0]]
        snd.note_acks(b)
        off=0
        while len(b)-off>=HDR.size:
            c,cmd,frg,wnd,ts,sn,una,ln=HDR.unpack_from(b,off)
            if c!=conv: break
            pl=b[off+HDR.size:off+HDR.size+ln]; off+=HDR.size+ln
            if cmd!=81 or len(pl)<0x10: continue
            lead=struct.unpack_from('<I',pl,0)[0]
            if lead in (0x11,0x13): continue
            iot=struct.unpack_from('<I',pl,0xc)[0]; dl=struct.unpack_from('<I',pl,8)[0]
            if dl<=512: out.append((iot,pl[0x10:0x10+dl]))
        rcv.input(b)
        ak=rcv.ack_segments()
        for i in range(0,len(ak),8): s.sendto(build(0x1409,b"".join(ak[i:i+8]),aux=0x21),(CAM,sport))
    return out
pump(2.0)
ok=None
for _ in range(4): s.sendto(encode(cfg.build_knock(os.urandom(4),cl,0x00,idx)),(CAM,sport)); time.sleep(0.1)
t=time.monotonic()+1.2
while time.monotonic()<t:
    try: d,_=s.recvfrom(65535)
    except socket.timeout: continue
    try: dd=decode(d)
    except Exception: continue
    if dd[:4]==MAGIC and mt(dd)==0x130c: ok=stt(dd)
if ok!="0000": raise SystemExit(f"knock failed {ok}")
for _ in range(4): s.sendto(encode(cfg.build_confirm(os.urandom(4),cl,0x00,idx)),(CAM,sport)); time.sleep(0.08)
print(f"session ready (index={idx})\n")
for iot,data,name in QUERIES:
    seg=snd.push(build_ioctrl_frame(0,iot,data),una=rcv.rcv_nxt,ts=ms())
    s.sendto(build(0x1409,seg,aux=0x21),(CAM,sport))
    res=pump(4.0)
    hits=[r for r in res if r[0]!=0]
    print(f"{name} (io={iot}) -> {len(hits)} KCP response frame(s); msgtypes={dict((hex(k),v) for k,v in SEEN.items())}")
    for rio,rd in hits[:3]:
        print(f"   io={rio} len={len(rd)}")
        for o in range(0,min(len(rd),96),16):
            ch=rd[o:o+16]; txt=''.join(chr(x) if 32<=x<=126 else '.' for x in ch)
            print(f"     +0x{o:03x} {ch.hex(' ')} |{txt}|")
    print()
s.close()
print(f"\nRAW 0x1402 packets: {len(RAW)}")
for d in RAW[:4]:
    print(f"   hdr[0xc:0x10]={d[12:16].hex()} body({len(d)-16}B): {d[16:16+72].hex()}")
