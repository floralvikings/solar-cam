# Protocol Notes — RBX-S73

Reverse-engineering notes on the wire protocol(s). Evidence base: idle capture
`rbx-idle.pcap` (2026-07-22, 341s, camera `192.168.88.113`).

> ⚠️ **REDACT BEFORE PUBLISHING:** the header bytes below very likely encode
> the device UID / session identity. Do not publish them verbatim.

## Platform identification — **Confirmed**

The camera talks to **`ubianet.com`** — the **UBIA** cloud platform (matches the
"UBox" app). This is a cloud-brokered P2P camera platform, not ONVIF/RTSP.

## Channels observed at idle

| Channel | Transport | Remote | Camera src port | Purpose (inferred) | Confidence |
|---------|-----------|--------|-----------------|--------------------|-----------|
| Rendezvous / lookup | **UDP 10240** | `m2`,`m4`.ubianet.com + peers | 49280, 33900 | Register + look up peers; same packet sent to a *pool* of servers | Strongly indicated |
| Control / keepalive | **UDP 20001** | 4 media servers | 33900 | 2 pkts / 548 B every **~30 s** | Confirmed |
| Persistent control | **TCP 443** (NOT TLS) | same 4 media servers | ephemeral | 20–37 B messages every **~6–10 s** to all four | Confirmed |
| Media / event upload | **UDP 20001** | `170.101.97.156` | 33900 | ~336 KB burst, 1320 B packets, entropy 7.5 | Strongly indicated |

### TCP 443 is **not** HTTPS — **Confirmed**
511 packets on port 443, **zero TLS handshakes** (`tls.handshake` → 0). Payload
sizes 20/24/32/36/37 B (plus 192/224 B). The camera holds persistent TCP
connections to 4 servers and heartbeats them. Port 443 is used to look like
HTTPS and traverse restrictive firewalls. Blocking 443 by port alone will not
be selective enough — block by destination IP/host.

### Port 80 traffic is **not** HTTP — **Confirmed**
`http.request` → 0. The camera opens TCP connections to Akamai/CloudFront IPs
and never sends a request: a pure **TCP reachability test** (see the
connectivity-check loop below).

## Packet header fingerprints

First 16 bytes, by direction and port (idle capture):

```
camera -> server  :20001    54a58d 0d62bdd8d2254d498d 6ccbcbd4
server -> camera  :20001    14a09d 2d62bcd8d2254d498d accacbd4
camera -> server  :10240    84a58d 0d62bdd8d2254d498d 6ccbcbda
server -> camera  :10240    04ac9d 2d62bcd8d2254d498d accacbd2
```

Observations:
- A **shared constant** `d8d2254d498d` appears in *every* direction and on both
  ports → almost certainly the **device UID / session ID**, obfuscated.
- Direction is encoded in the first bytes: camera→server begins `54a58d`/
  `84a58d`; server→camera begins `14a09d`/`04ac9d`. Byte 0 differs by a single
  bit pattern (0x54/0x84, 0x14/0x04) → likely a type/flags nibble.
- Bytes differ only slightly between the two ports and directions (`62bd` vs
  `62bc`, `6ccbcbd4` vs `accacbd4`) → the payload is **XOR/rolling-mask
  obfuscated**, not strongly encrypted. Tag: **Possible** (needs a second
  capture to confirm the mask is static).
- The **identical 16-byte header is repeated 6× to several different servers**
  on UDP 10240 → a broadcast-style registration/lookup to a server pool.

## Entropy (encryption assessment)

| Traffic | Entropy (bits/byte) | Reading |
|---------|--------------------|---------|
| Control pkts (10240/20001) | 4.87 – 6.34 | Structured/obfuscated, **not** strongly encrypted |
| Media burst (20001) | **7.50** | Encrypted **or** compressed video — **Strongly indicated** |

The low control-plane entropy is the encouraging part: control/command packets
look reversible. The media stream will be the hard part.

## Platform: **rebranded ThroughTek TUTK** — **Confirmed** (APK, 2026-07-23)

The UBox APK bundles `libUBICAPIs.so`, a TUTK fork (`IOTC_*` → `UBIC_*`), with
the literal string `com/tutk/IOTC/st_LanSearchInfo2` and matching `IOTC_ER_*`
error codes. See `apk-analysis.md` for the full evidence, the `p4p_*` API, and
the **494-constant command table** (`AVIOCTRLDEFs.java`) giving the PTZ,
streaming, playback, and file-download opcodes.

⇒ The observed UDP 10240 rendezvous + UDP 20001 media pattern is the TUTK
IOTC/AVAPI session model: `UID → rendezvous → deviceSID/clientSID → AV channel`.

### Local (cloud-free) operation looks viable — **Strongly indicated**
The SDK defines `CLI_SESSION_LAN = 5` alongside `CLI_SESSION_P2P = 4`, exposes
`p4p_mgmt_setnetmode()`, and the camera side implements
`p4p_device_handle_lansearchreq` — i.e. **the camera answers a proprietary UDP
LAN-discovery broadcast**. That is why SSDP/ONVIF/mDNS probes found nothing:
we were speaking the wrong protocol, not talking to a silent device.

## 🔓 LAN discovery WORKS — **Confirmed** (2026-07-23)

The camera answers a proprietary LAN-discovery request on **UDP 32762**,
replying **directly to an arbitrary LAN host** (our Mac) with no cloud and no
phone involved. This is the first proven cloud-free channel to the device.

### Request (36 bytes, **plaintext**)
Recovered by capturing the UBox app's startup broadcast to
`<subnet>.255:32762`, then reproduced byte-for-byte by
`scripts/probe_camera.py --uid <UID>`:

```
offset  0   07 18 10 00        fixed prefix
offset  4   24 00              uint16 LE total length (0x0024 = 36)
offset  6   01 13              message type
offset  8   <20 ASCII UID> 00  device UID, null-terminated
offset 29   fe 3d 03 00 00 00 00
```

⚠️ The 20-char UID is a **device secret** — it is the camera's address on the
P2P network. Never commit it; pass it via `--uid` at runtime.

The app broadcasts this ~33× at ~200 ms intervals (retry behaviour).

### Response (408 bytes, obfuscated) — **DECODED** ✅

The obfuscation is fully reversed. It is not encryption: a fixed transform with
a **hardcoded key** shipped in every copy of the app. Implemented in
`scripts/pcaptools/ubia_crypto.py` (`encode`/`decode`), verified to reproduce
real wire bytes exactly, 12 unit tests.

**Transform** (from `libUBICAPIs.so`; SDK calls it `p4p_crypto_encode`), per
16-byte block:
1. `p4p_DWORDbitshift` — rotate each 4-byte LE word right by (offset+1) → 1,5,9,13
2. `p4p_XOR` with the 32-byte key (blocks use the first 16 bytes)
3. `p4p_Swap` — fixed 16-byte permutation `[11,9,8,15,13,10,12,14,2,1,5,0,6,4,7,3]`
4. `p4p_DWORDbitshift` — rotate each word right by (offset+3) → 3,7,11,15

Trailing partial block: XOR+Swap only, no rotations.

**The key** (`.rodata` 0xb7b1, hardcoded ASCII, 32 bytes):
```
I believe 1 ^ill win the battle!
```
This is not a secret — it is identical for every device/app install — so it is
safe to keep in the repo. Device UIDs and passwords are the secrets.

**Decoded LAN-search response** (a `LanSearchInfo` record):
```
07 18 10 00        magic
88 01              uint16 LE length (0x0188)
90 a8              ...
02 13              msgtype 0x1302  (response; request was 0x1301)
<20-byte device UID> "1"
<account username>       <- e.g. "admin"
<credential/token string>
...mostly-empty padding records...
8-byte ascii trailer token
```

### ⚠️ SECURITY FINDING — credentials exposed on the LAN
The camera returns the **device UID, the account username, and a credential
string** to *any* LAN host that sends the (plaintext) LAN-search request — no
authentication. After the trivial deobfuscation above, these are cleartext.
This is our route to local access **and** a genuine vulnerability worth noting
in `cloud-dependencies.md`. These values are treated as secrets and kept out of
the repo (`.gitignore` + a pre-commit-style scan).

The same transform is used on the **cloud** channels too (shared header family
`…2d62bcd8d2…`), so `ubia_crypto.decode` should also open the UDP 10240/20001
and TCP 443 payloads for analysis.

### Resolved: no cloud wake needed — just a radio warmup — **Confirmed**
Tested cold (camera untouched, app closed). Pattern across a 10-round probe:
first ~2 rounds (~5–7 s) silent, then **8/8 replies**. The camera answers
ICMP even while power-saving, but its P4P LAN responder only replies once the
Wi-Fi radio is fully up; a few seconds of repeated probing spins it up, after
which it answers reliably. The cold reply decodes identically (magic
`07181000`, msgtype `0x1302`, correct UID).

⇒ **Local access does not depend on the cloud.** `CLI_SESSION_WAKEUP` is about
P2P session state, not a cloud precondition for LAN discovery. Practical
implication for the bridge: on connect, **retry LAN-search for ~5–10 s** to
allow radio warmup before giving up. High, variable ping RTT (250–730 ms) is
consistent with 802.11 power-save (DTIM buffering).

## Cloud control protocol — DECODED (2026-07-23, from `rbx-idle.pcap`)

Running `ubia_crypto.decode` over the idle capture's cloud payloads: **every**
UDP 10240/20001 payload decodes to the P4P magic `07181000`. TCP 443 is a
separate, **plaintext** channel. Header framing:

```
07 18 10 00 | <u16 LE length> | <u16 msgtype> | <session/flags> | body...
```

### Message-type map (msgtype at offset 8, LE) — **Confirmed**
| msgtype | Dir | Port | Meaning |
|---------|-----|------|---------|
| `0x1001` / `0x1002` | cam↔srv | 10240 | Rendezvous **lookup** (register UID / get server+peer list) |
| `0x1101` / `0x1102` | cam↔srv | 20001 | **Session connect** req/resp |
| `0x1105` / `0x1106` | srv↔cam | 20001 | **Peer address exchange** (LAN/WAN) — hole-punch |
| `0x110d` / `0x110e` | cam↔srv | 20001 | Session sub-negotiation (small) |
| `0x1301` / `0x1302` | local | 32762 | **LAN search** (see above) |
| `0x1406` / `0x1409` | cam↔srv | 20001 | Keepalive (carries session id `37e027d9`) |
| `0x140a` | cam→srv | 20001 | **Bulk data / media upload** (the 336 KB event clip) |

### 🔑 Hole-punching confirmed — direct P2P is the intended path
In the session-setup messages the cloud exchanges each peer's **LAN** address:
- `0x1105` (srv→cam) contains the **phone's** LAN addr `192.168.88.111:34755`
- `0x1106` (cam→srv) contains the **camera's** LAN addr `192.168.88.113:33900`

(plus a consistent NAT-mapped **WAN** address — the site's public IP, redacted).
This is classic ICE/STUN-style rendezvous: the cloud brokers the introduction,
then peers connect **directly**. When phone and camera share a LAN, video should
flow **phone↔camera directly**, not via the cloud. Tag: **Strongly indicated**
(confirm with the live-view capture; the idle capture has no phone-side view).

⇒ **Bridge strategy:** a local daemon can act as the *client peer* — do the LAN
search, open a session, and receive the AV stream directly from the camera on
the LAN, skipping the cloud (which the LAN-search path already proves reachable).

### TCP 443 — plaintext presence channel (NOT P4P, not TLS) — **Confirmed**
Bytewise ASCII key/value, no obfuscation:
- cam→srv: `uid=<UID>`, `hostalive=<UID>…`, `iotalive=<UID>…` (heartbeats)
- srv→cam: 32-byte status records (`<UID> + 12 bytes`), repeated

### Media body (`0x140a`) — still opaque
The `0x140a` header decodes, but the bulk body stays high-entropy after
deobfuscation (matches the earlier 7.5 bits/byte) → the AV payload is
compressed/encrypted **beneath** the transport obfuscation. Decoding the AV
codec is a later, separate problem from getting a local session.

## Connectivity-check loop (noise, not protocol) — **Confirmed**

86% of the idle capture (8,768 packets) is DNS. The camera repeatedly resolves
8 well-known sites (~1,040 queries **each** in 5.7 min):
`www.microsoft.com, www.amazon.com, www.qq.com, www.apple.com, www.baidu.com,
www.google.com, www.jd.com, www.taobao.com`, and TCP-connects to their CDNs on
port 80 without sending a request.

It is **bursty, not constant**: silent t=30–150 s, then ~1,000 queries per 30 s
(~34/s) during t=180–270 s — correlating with the media upload burst. So the
check loop spins up when the camera does cloud work.

Also queries NTP: `pool.ntp.org`, `0/1/2.pool.ntp.org`,
`2.north-america.pool.ntp.org`, `hk.ntp.org.cn`, `de.ntp.org.cn`,
`uk.ntp.pool.org`.

## LOCAL CONTROL — **Solved** (2026-07-25)

Full cloud-free control works over pure LAN. Established by reversing the device
SDK (`apk/native/libUBICAPIs.so`) and confirmed live against the camera.

### Session establishment (ioctrl-capable)
1. LAN-search (0x1301) wakes the camera; it replies with its view-password.
2. **lanstreamreq (0x1307)** → camera opens a session port and replies **0x1308**.
   The camera allocates a per-client session slot at a **device-chosen random
   index**, echoed in the 0x1308 response after a `04 01 00 00 00` marker at
   `resp[0x42]`, so the index byte is **`resp[0x47]`** (it is 0 in the common
   case, which hid an earlier off-by-one vs `resp[0x46]`). It stores our `conv`
   (request `body[72]`) and our `body[3]` as slot check-fields.
3. Stream video (KCP over 0x140a; ACK with 0x1409) to bring the session up.
4. **knock (0x130b)** — auth is a *plaintext* memcmp of UID + view-password +
   `"admin"` (no crypto). The knock's `pkt[0x3b]` MUST equal the device-assigned
   index; `pkt[0x40]`=conv; `pkt[0xf]`=`0`. Camera replies **0x130c status=0000**.
5. **confirm (0x130d)** — `pkt[0x2b]`=index, `pkt[0xf]`=0. Completes the 2-step
   handshake (marks the slot established). Required before ioctrl is dispatched.

### ioctrl transport (PTZ / commands)
Commands ride the **avchn's KCP reliable channel** (same conv as video, wrapped
in obfuscated **0x1409**, client→device PUSH), NOT a raw datagram. One KCP stream
carries video + control + telemetry, demuxed by a leading type word:

| Frame | Leading word | Layout |
|-------|-------------|--------|
| ioctrl request (client→device) | `[0:2]=3` | `[2]=avchannel` `[8:12]=datalen` `[0xc:0x10]=iotype` `[0x10:]=data` |
| ioctrl response (device→client) | `[0:4]=4` | `[8:12]=datalen` `[0xc:0x10]=iotype` `[0x10:]=data` |
| telemetry (device→client) | `[0:4]=0x11` | 53-byte periodic status (ts+counter; battery/PIR? — undecoded) |

### Command IDs

| Action | iotype | Payload | Confidence |
|--------|--------|---------|-----------|
| Pan/Tilt | 4097 (`PTZ_COMMAND_REQ`) | 8B `SMsgAVIoctrlPtzCmd`; control byte (ENUM_PTZCMD: LEFT=6 RIGHT=3 UP=1 DOWN=2 STOP=0); exact field order tentative | Transport confirmed; camera replies iotype 4096 echoing control. Physical motion pending user confirmation |
| Device info | 816 (`DEVINFO_REQ`) | 4 zero bytes | Sent; no reply on this camera (may be unsupported) |
| Light (white/flood) | `SET_LIGHT_TABLE` 4676 is a *schedule table*, not on/off | — | Unknown; needs an app-PTZ/light capture |
| SD playback | FILE_LIST 4864 / FILE_DOWNLOAD 4866 | — | Untested |

### Implementation
- `p4p.session.build_knock` / `build_knock_confirm`, `p4p.kcp.KcpSender` /
  `build_ioctrl_frame`, and `p4p.client.LanControlSession` (video + control on one
  session, driven by a Unix control socket).
- HA integration: PTZ buttons → `coordinator.async_send_control` → the control
  socket into the live `capture.py` session.

## Open questions
- Does PTZ physically move the motor with the current struct encoding, or is the
  field order / a motor-wake state off? (resolve with an app-PTZ LAN capture)
- Exact `SMsgAVIoctrlPtzCmd` field order (aux/channel/control/limit/point/speed).
- Decode the 53-byte `0x11` telemetry frames (battery %, PIR, status).
- Is the obfuscation mask static across sessions/devices?
