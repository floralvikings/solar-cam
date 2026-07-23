# Direct LAN Session Flow — RBX-S73 (from SDK trace)

Reconstructed from `libUBICAPIs.so` (ULOG format strings + disassembly, 2026-07-23)
and the live capture. This is the recipe a local bridge must implement to pull
AV from the camera without the cloud.

## Architecture in one line

```
mgmt_init → client makes randomID → LAN-search (32762) → preconnect/PUNCH2LAN
          → session (deviceSID/clientSID) → KCP channels → lanstreamreq → AV frames
```

Everything runs over **UDP**, with a **KCP** reliable-ARQ layer for the data/AV
channels, and the P4P obfuscation (`ubia_crypto`) on the control packets.

## Transport: KCP (ikcp) — **Confirmed**

The binary contains the full `ikcp` implementation
(`ikcp_create/input/flush/getconv`, `IKCP_CMD_PUSH/ACK/WASK/WINS`,
`IKCP_MTU_DEF`, `IKCP_RTO_*`). This is stock KCP
(github.com/skywind3000/kcp) — a documented reliable-UDP protocol with a
24-byte header `[conv|cmd|frg|wnd|ts|sn|una|len]`. **We can use an existing KCP
library** instead of reversing the reliability layer.

Log lines tie one KCP object per AV channel to the session:
`avid:%d sid:%d cid:%d rlysid:%d kcp:%p randomID:%08x`. The KCP **conv** is
almost certainly the `randomID` (to verify empirically).

## Three stream modes — we want **LAN**

The SDK explicitly distinguishes, in `STREAMREQ_COST` logging and code paths:
| Mode | Client sender | Device handler | When |
|------|--------------|----------------|------|
| **LAN** | `p4p_client_send_lanstreamreq` | `p4p_device_handle_lanstreamreq` | peer reachable on LAN IP ← **our target** |
| P2P | (hole-punched) | | different NATs, direct |
| RLY | `p4p_client_send_rlystreamreq` | `p4p_device_handle_rlystreamreq` | fallback via cloud relay |

## ⚡ Simplified LAN path — **Confirmed** (2026-07-23, from `handle_lansearchrsp`)

On the **LAN**, the connection is far shorter than the general P2P flow below.
Disassembly of `p4p_client_handle_lansearchrsp` shows that after it parses the
reply, stores the device addresses, and starts a timer, its **final action is a
direct call to `p4p_client_send_lanstreamreq`** — there is **no separate
preconnect / knock / login on the LAN path** (those exist for NAT traversal in
P2P/RLY mode). The LAN-search reply already carries `deviceSID` + addresses.

```
LAN-search (32762)  →  parse LanSearchInfo (deviceSID, addrs)
                    →  send_lanstreamreq (msgtype 0x1307, UDP → camera)
                    →  camera streams H.264 over KCP
```

`p4p_client_send_lanstreamreq` (verified): writes **msgtype `0x1307`**, sends via
`p4p_send_udp` to the camera (it tries LAN + pub addrs; on-LAN the LAN addr
wins), and its body memcpy's the UID (20B) plus 16-byte session/stream structs
taken from the LanSearchInfo. `getnetmode` gates LAN vs relay.

**This is the whole recipe for first video.** The general flow below applies to
P2P/relay (off-LAN) only.

### `lanstreamreq` packet layout — from `send_lanstreamreq` disassembly

Header (standard 16-byte, then whole packet obfuscated by `send_udp`):
```
magic 07181000 | len 0x006c (108) | flags 0x0000 | msgtype 0x1307 | aux 0x0021 | resv 0x00000000
```
Total = 16 + 108 = **124 bytes**. `aux=0x21` and `body[0]=0x01` are constants for
the stream-start request.

Body (108 bytes) is copied from the device-session struct `sess` (populated by
`handle_lansearchrsp` from the LAN-search reply). Field map (body offsets):
| body[] | size | source | meaning (inferred) |
|--------|------|--------|--------------------|
| 0 | 1 | const `0x01` | stream on |
| 3 | 1 | `sess+0x17` | ? |
| 24..44 | 20 | `sess+0xe4` | **device UID** |
| 44..108 | 64 | `sess+0x108` | session/stream/address block |
| 65 | 1 | `sess+0xe0` | ? |
| 66 | 1 | `sess+0x06` | ? |
| 72..76 | 4 | `sess+0x0c` | u32 (session id / randomID?) |
| 76..92 | 16 | `sess+0xf8` | 16B block (overwrites part of the 64B) |
| 92 | 1 | 9 or 0 | device-type dependent |
| 94 | 1 | `sess+0xe1` | ? |
| 100..104 | 4 | `sess+0x128` | u32 (stream index / quality?) |

Sent via `p4p_send_udp` (obfuscates) to the camera's LAN addr, pub addr, and —
per `getnetmode` — a third target (relay). On-LAN, the LAN addr is used.

**To pin next:** the `sess` fields come from the LAN-search reply. Map the
reply→`sess` parsing in `handle_lansearchrsp` to fill these from the
`LanSearchInfo` we already decode; the `sess+0x108` block is likely the
device's address/stream descriptor echoed from the reply. Then send a candidate
`lanstreamreq` to the camera and read the response (`handle_lanstreamrsp`) — our
own Mac↔camera traffic is visible, so we can iterate empirically.

Remaining after that: the KCP receive side (`handle_lanstreamrsp` → KCP frames).

### ✅ VERIFIED LIVE (2026-07-23): camera accepts `lanstreamreq`, opens session

Sent a candidate `lanstreamreq` (msgtype 0x1307, aux 0x21, body = const `0x01` +
UID, rest zero) to the camera at `:32762`. The camera **accepted it** and
replied **msgtype `0x1308`** from a **freshly-opened session UDP port**, body:
```
b[12:16] = camera LAN IP        (c0 a8 58 71 = 192.168.88.113)
b[16:18] = session port (BE)    (d1 40 = 53568; ephemeral per session)
b[24:28] = session id           (2b f8 00 00; candidate KCP conv)
b[28:48] = UID (echo)
b[48:52] = 00 00 00 01          (flag/count)
```
The camera **retransmits `0x1308` until the client connects** to that session
port — i.e. the next step is the **KCP handshake on the session port**, after
which the camera streams H.264. Implemented in `p4p.session`
(`build_lanstreamreq`, `parse_lanstreamrsp`).

**So even a near-empty stream request works** — the camera only needs the UID to
start a session. Next: `handle_lanstreamrsp` to learn what the client sends to
the session port (KCP conv/handshake) to make video flow.

## State machine (client peer side) — general (P2P/relay)

1. **`p4p_mgmt_init`** — allocate the 4 crypto buffers (`p4p_crypto_init`), etc.
2. **`p4p_client_randomID`** — client generates a 32-bit `randomID` (the session
   correlation id / KCP conv).
3. **LAN search** — `p4p_client_send_lansearchreq` broadcasts the 36-byte
   request to `<bcast>:32762` (msgtype **0x1301**, *confirmed on the wire*).
   Device `handle_lansearchreq` → replies with `LanSearchInfo` (msgtype
   **0x1302**): device UID, account, credential, `deviceSID`, addresses.
   *(Our `probe_camera.py --uid` already does this leg and decodes the reply.)*
4. **Preconnect / PUNCH2LAN** — client sends a preconnect to the camera's **LAN
   IP** carrying `randomID` + `clientLanAddr` + `clientPubAddr`. Device
   `handle_preconnectreq` logs
   `add deviceSID:%d, randomID:0x%08x, clientLanAddr:0x%08x clientPubAddr:0x%08x`
   and registers the session; client log `sid:%d randomID:%08x, PUNCH2LAN`.
   Candidate msgtype ~**0x110a** (verify).
5. **Session up** — both sides hold `deviceSID`/`clientSID`; KCP channel(s)
   created keyed by `randomID`.
6. **Start video** — `p4p_client_startvideo` → `p4p_client_send_lanstreamreq`
   (candidate msgtype **0x1307**), which references the stream/quality via the
   `SETSTREAMCTRL` ioctrl (`IOTYPE_USER_IPCAM_SETSTREAMCTRL_REQ = 800`,
   `streamindex`). Device `handle_lanstreamreq` starts pushing frames.
7. **AV delivery** — video/audio frames arrive over KCP per channel:
   `avidx:%d cid:%d streamindex:%d FN:%u tms:%u len:%u` (FN = frame number,
   tms = timestamp). H.264 (`sentIDR`, `VideoDrop` for non-IDR).
8. **Control** — `p4p_client_send_ioctrl` (candidate msgtype **0x1401**) carries
   the `AVIOCTRLDEFs` opcodes (PTZ etc.) on a control channel; device replies
   via `device_send_ioctrl_ext` (**0x1402**).

## Confirmed vs candidate msgtypes
- **Confirmed (on the wire):** LAN-search `0x1301` req / `0x1302` rsp;
  cloud rendezvous `0x1001/2`, session `0x1101/2`, peer-exch `0x1105/6`,
  keepalive `0x1406/9`, media `0x140a`; client-cloud `0x1051/2`, `0x1201/2`.
- **Candidate (disassembly, verify empirically):** ioctrl `0x1401/0x1402`,
  lanstreamreq `0x1307`, rlystreamreq `0x1205`, preconnect `~0x110a`.
  (Static immediate-extraction is noisy; confirm by watching our own client's
  traffic — which is visible on the Mac since it's to/from us.)

## Build plan for the bridge (Phase 2)

1. **`p4p` client library** (Python first, for iteration):
   - LAN-search (have it) → parse `LanSearchInfo` for `deviceSID` + addrs.
   - Generate `randomID`; send preconnect to camera LAN IP; complete handshake.
   - Wrap a KCP library (e.g. a Python `ikcp` port) with conv=`randomID`.
   - `send_ioctrl(SETSTREAMCTRL)` + `lanstreamreq`; receive H.264 frames.
   - All control packets go through `ubia_crypto.encode/decode`.
2. **Verify each step against our own Mac↔camera traffic** (tcpdump on the Mac;
   our packets are visible). Pin the candidate msgtypes and field offsets here.
3. **Re-serve**: feed the H.264 elementary stream to **go2rtc/MediaMTX** → RTSP
   → Home Assistant/Frigate.

Open items to pin during Phase 2: exact preconnect/lanstreamreq byte layout,
KCP conv derivation, per-channel `cid` assignment, and whether AV frames are
additionally encrypted beneath KCP (idle `0x140a` body was high-entropy — may
just be H.264, to be confirmed on a decrypted LAN stream).
