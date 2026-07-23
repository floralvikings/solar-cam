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

## State machine (client peer side)

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
