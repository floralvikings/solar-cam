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

### Response (408 bytes, obfuscated)
```
25 x 16-byte blocks  +  8-byte ASCII trailer ("2udb5ekC"-style token)
11 unique blocks; one block repeats 15x (empty/padding records)
```
Analysis so far:
- Identical plaintext → identical ciphertext at 16-byte alignment ⇒ a
  **static, position-independent block transform**.
- **Not** a strong block cipher: different message types share long common
  prefixes and differ in only a few bytes
  (`04a48c0d62bcd8d2…` LAN vs `04ac9d2d62bcd8d2…` cloud/10240), where AES
  would avalanche. Tag: **Strongly indicated.**
- The UID is **not** recoverable by single-byte XOR nor by any repeating XOR
  key of period 4/8/16. So it is more than trivial XOR (substitution table or
  similar), or the UID simply is not echoed. Tag: **Confirmed** (negative).
- The response shares the header family of the cloud traffic
  (`…2d62bcd8d2…`), i.e. one transform is used on both LAN and cloud paths.

**Next:** locate the transform in `libUBICAPIs.so` rather than guess — see
`apk-analysis.md`.

### Open question: does the camera need waking first?
The first probe attempt got **no reply**; a reply arrived on a later attempt
(~7 s into a repeated probe loop). Cause not yet isolated — either the camera
must be woken (cf. `CLI_SESSION_WAKEUP = 1`) or the single-shot attempt simply
missed. **Re-test on a camera left untouched for a while, without opening the
app**, to settle it.

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

## Command IDs (pan/tilt/wake/live/playback)

Not yet determined — requires single-action captures. Compare with
`compare_sessions.py`, then diff payloads to locate the opcode.

| Action | Distinguishing flow | Payload delta / opcode | Confidence |
|--------|--------------------|------------------------|------------|
| Wake | | | Unknown |
| Live view start | | | Unknown |
| Pan / Tilt | | | Unknown |
| SD playback | | | Unknown |

## Open questions
- Is the obfuscation mask static across sessions/devices? (needs 2nd capture)
- Does the phone ever talk **directly** to the camera, or always via relay?
- Can a LAN peer initiate a session without the cloud?
