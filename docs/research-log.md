# Research Log — RBX-S73

Chronological log of what was done, what was observed, and what it means.
Newest entries at the top. Keep **observed facts** separate from
**hypotheses**, and tag conclusions: **Confirmed / Strongly indicated /
Possible / Unknown**.

> Redaction note: full MAC / device UID are kept out of committed docs
> (recorded only in the operator's local notes). OUI + RFC1918 IPs are fine.

---

## 2026-07-23 — LAN discovery works; obfuscation fully broken

**Conditions:** Mac (`192.168.88.20`) and camera on the same LAN. Two parts:
(a) captured the UBox app's LAN-search broadcast; (b) static analysis of
`libUBICAPIs.so` with pyelftools + capstone.

**Observed (facts):**
- Captured `captures/lansearch.pcap`: the app broadcasts a **36-byte plaintext**
  request to `<subnet>.255:32762` ~33× at ~200 ms; carries the 20-char device
  UID with a uint16-LE length at offset 4 (see `protocol-notes.md`).
- Reproduced the request with `probe_camera.py --uid` and the **camera replied
  directly to the Mac** from `192.168.88.113:32762` with a **408-byte** response
  — no cloud, no phone. First reply came ~7 s into a repeated probe *while live
  view was open* (see wake question below).
- Response is obfuscated: 25×16-byte blocks + 8-byte ascii trailer.
- `libUBICAPIs.so` symbol table exposed the routines directly: `p4p_XOR`,
  `p4p_Swap`, `p4p_DWORDbitshift`, `p4p_crypto_encode/decode/init`, and a
  hardcoded key in `.rodata`.
- Disassembly → the transform is: per 16B block, ROTR words by (off+1), XOR
  32-byte key, Swap16 (fixed permutation), ROTR words by (off+3). **Key =
  `"I believe 1 ^ill win the battle!"`** (hardcoded, same for all installs).
- Implemented `pcaptools/ubia_crypto.py`; it **round-trips real wire bytes**
  and decodes the response to plaintext: magic `07181000`, msgtype `0x1302`,
  the device UID, the account username, and a credential string.

**Interpretation:**
- **Cloud-free local access is real.** Tag: **Confirmed.** We can discover the
  camera and read its identity/credentials over pure LAN.
- The "encryption" is keyless-in-practice obfuscation. Tag: **Confirmed.**
- **Security finding:** the camera hands UID + account + credential to *any*
  unauthenticated LAN host. Tag: **Confirmed.** Logged in
  `cloud-dependencies.md`. Secrets kept out of git.
- One transform covers LAN **and** cloud (shared header family) → we should be
  able to decode the earlier UDP 10240/20001 + TCP 443 captures too.

**Wake question — RESOLVED (same day):** cold re-probe (camera untouched, app
closed) → 10-round test showed first ~2 rounds silent, then **8/8 replies**;
cold reply decodes identically. So it is a **Wi-Fi radio warmup**, not a cloud
wake: the camera answers ICMP while power-saving but its P4P LAN responder needs
the radio fully up (~5–7 s of probing). **Local discovery does not need the
cloud.** Tag: **Confirmed.** Bridge should retry LAN-search ~5–10 s on connect.

**Next experiment:**
1. ~~Cold re-probe~~ done — warmup, not cloud-wake.
2. ~~Decode cloud payloads~~ done — see next entry.
3. Map the LanSearchInfo response fields; then try a full LAN session
   (`send_ioctrl` with the PTZ opcodes).

---

## 2026-07-23 — Cloud payloads decoded; hole-punch signaling confirmed

**Conditions:** offline analysis of `rbx-idle.pcap` with `ubia_crypto.decode`.
No camera interaction.

**Observed (facts):**
- **Every** UDP 10240/20001 payload decodes to P4P magic `07181000` with the
  same transform used for LAN search. Header: `07181000 | u16 len | u16 msgtype`.
- Message-type map (Confirmed): `0x1001/2` rendezvous lookup (10240);
  `0x1101/2` session connect, `0x1105/6` peer-address exchange, `0x1406/9`
  keepalive, `0x140a` bulk/media upload (20001); `0x1301/2` LAN search (32762).
- **TCP 443 is plaintext**, not P4P and not TLS: `uid=<UID>`, `hostalive=<UID>`,
  `iotalive=<UID>` heartbeats cam→srv; 32-byte `<UID>+12B` status records
  srv→cam.
- Session-setup carries **LAN addresses of both peers**: `0x1105` (srv→cam)
  has the phone `192.168.88.111:34755`; `0x1106` (cam→srv) has the camera
  `192.168.88.113:33900`; plus a repeated NAT-mapped WAN IP (redacted).
- `0x140a` media body stays high-entropy after deobfuscation (AV is
  compressed/encrypted beneath the transport layer).

**Interpretation:**
- Whole cloud control plane is now readable with our codec. Tag: **Confirmed.**
- Cloud is a **rendezvous/hole-punch broker**; direct phone↔camera P2P is the
  intended data path on a shared LAN. Tag: **Strongly indicated** (needs the
  live-view capture to see the media actually flow phone↔camera).
- **Bridge plan crystallizing:** a local daemon acts as the *client peer* — LAN
  search → session connect → receive AV directly from the camera, no cloud.

**Next experiment:**
1. ~~Live-view capture~~ done — see next entry.
2. Map session fields; replay a minimal LAN session + `send_ioctrl` PTZ.

---

## 2026-07-23 — Live view is DIRECT phone↔camera P2P — **Confirmed**

**Conditions:** MikroTik bridge sniffer, filtered to camera `.113` + phone
`.111`, during ~40 s of live view + pan. `captures/rbx-live.pcap` (2140 pkts,
374 KiB, **8.6 KB/s** — no video-scale flow anywhere).

**Observed (facts):**
- **Zero** packets between phone `.111` and camera `.113` in the router capture,
  and **no high-bandwidth flow at all** (largest UDP conv ~3 KB). Live view and
  pan worked on the phone throughout.
- The phone broadcast a **LAN-search to `192.168.88.255:32762`** (~31 pkts over
  3.2 s) whose payload is **byte-identical** to our reconstructed request.
- Phone↔cloud signaling is small and client-side: `0x1051/0x1052` (lookup, to
  `m*.ubianet.com:10240`), `0x1201/0x1202` (session, to `…:20001`). The cloud
  responses to the phone do **not** contain the camera's LAN address.

**Interpretation:**
- **Live AV goes directly phone↔camera, L2-bridged in the Wi-Fi AP** (hence
  invisible to the router and zero-volume there). Tag: **Confirmed.**
- The client locates the camera via **LAN search**, not the cloud, when on the
  same LAN. Cloud is used only for a lightweight parallel rendezvous/keepalive.
  Tag: **Confirmed.**
- Answers CLAUDE.md Q4/Q7/Q11: phone talks **directly** to camera; video is
  **direct** not relayed (on-LAN); **LAN-only operation works**.

**Strategic consequence — the local path is fully mapped:**
`LAN-search(32762)` → camera replies with `LanSearchInfo` (UID/creds/session
params, already decoded) → client opens a **direct session** → AV streams P2P.
A bridge daemon replicates the *client peer*. Only the post-LAN-search session
handshake remains to be reversed; it is bridged in the AP so not visible to the
router — derive it from the SDK (`p4p_client_start`→`startvideo`) and iterate
our own client against the camera (our Mac↔camera traffic *is* visible to us),
using a monitor-mode/AP capture only if we get stuck.

**Next experiment:**
1. ~~Trace session flow in libUBICAPIs.so~~ done — see next entry.
2. Prototype a minimal LAN client (LAN-search → session connect).

---

## 2026-07-23 — SDK session-flow trace: KCP transport, LAN-punch flow

**Conditions:** static analysis of `libUBICAPIs.so` (ULOG format strings +
capstone disassembly of the `send_*` builders). Full detail in
`docs/session-flow.md`.

**Observed (facts):**
- Reliable transport is **KCP (ikcp)** — stock `ikcp_*` + `IKCP_CMD_*` symbols;
  one KCP object per AV channel, tied to `randomID` (`kcp:%p randomID:%08x`).
- Connection uses a client-generated **`randomID`** (`p4p_client_randomID`) then
  **`PUNCH2LAN`** / preconnect to the camera's LAN IP with `clientLanAddr` +
  `clientPubAddr`; device `handle_preconnectreq` registers the session.
- Three stream modes with distinct code paths: **LAN** / P2P / RLY
  (`send_lanstreamreq` vs `send_rlystreamreq`; `STREAMREQ_COST … (LAN|P2P|RLY)`).
- AV frames carry `avidx/cid/streamindex/FN/tms`; H.264 (`sentIDR`, `VideoDrop`).
- Candidate msgtypes from disassembly (noisy, to verify): ioctrl `0x1401/0x1402`,
  lanstreamreq `0x1307`, rlystreamreq `0x1205`, preconnect `~0x110a`.

**Interpretation:**
- Full local session recipe is now known end to end: `randomID → LAN-search →
  preconnect/PUNCH2LAN → KCP → lanstreamreq → H.264 over KCP`. Tag: **Confirmed**
  (architecture); msgtype constants **Strongly indicated**, to pin empirically.
- **KCP being stock is a major shortcut** — reuse an existing library rather than
  reverse the reliability layer.

**Next experiment (Phase 2 build):**
1. Prototype a Python `p4p` client: parse `LanSearchInfo` → preconnect → KCP →
   `lanstreamreq`, all control via `ubia_crypto`. Verify each step against our
   own Mac↔camera tcpdump (visible since it's our traffic). Pin the candidate
   msgtypes + field offsets.
2. Then feed the H.264 stream to go2rtc/MediaMTX → RTSP → Home Assistant.

---

## 2026-07-23 — UBox APK: SDK is a rebranded TUTK; LAN mode exists

**Conditions:** APK pulled via `adb` from an owned Galaxy S23 Ultra
(`cn.ubia.ubox`): `base.apk` 60 MB + `split_config.arm64_v8a.apk` 90 MB.
Decompiled with jadx (10,830 java files); native libs inspected via `strings`.

**Observed (facts):**
- Bundled P2P SDK is **`libUBICAPIs.so` — a rebranded ThroughTek TUTK**:
  the binary still contains `com/tutk/IOTC/st_LanSearchInfo2`; JNI exports are
  TUTK's `IOTC_*` renamed to `UBIC_*`; `IOTC_ER_*` error codes match TUTK's.
- `p4p_*` API includes `startvideo/startaudio/startspeak`,
  `send_ioctrl`, `send_avcommand`, `startlansearch`, `setnetmode`.
- Internal symbols include **`p4p_device_handle_lansearchreq`** (device side of
  LAN discovery) and `p4p_device_handle_preconnectreq`.
- `UBICAPIs.java` defines **`CLI_SESSION_LAN = 5`** (vs `CLI_SESSION_P2P = 4`),
  `CLI_SESSION_WAKEUP = 1`, `CLI_WRONG_VIEWACCPWD = -2005`.
- `com/ubia/IOTC/AVIOCTRLDEFs.java` holds **494 command constants**: full PTZ
  set (`PTZ_STOP=0, UP=1, DOWN=2, LEFT=3, RIGHT=6`, presets, cruise), stream
  control (800–809), playback (`RECORD_PLAY_START=16`), file/event download
  (4864–4877), `IOTYPE_UBIA_SET_UID_REQ=241`.
- SDK-embedded endpoints: `portal{,.us,.cn}.ubianet.com`, `oam.ubianet.com`,
  `d.ubianet.com`, `d.ntp.ubianet.com`, and regional media buckets
  `ubiasnap-{as,eu,us}.oss-*.aliyuncs.com` / `.s3-*.amazonaws.com`.
- `www.amazon.com` is embedded **in the SDK** → the connectivity-check loop
  seen in the idle capture is SDK behavior, not app behavior.

**Interpretation:**
- Platform is TUTK-derived. Tag: **Confirmed.** This is a large win — the
  TUTK IOTC/AVAPI model is publicly documented, so the remaining work is
  mapping a known protocol rather than reversing an unknown one.
- **A cloud-free LAN session is plausible**: LAN session type + `setnetmode` +
  a device-side LAN-search handler. Tag: **Strongly indicated** (not yet
  demonstrated against this camera).
- Earlier "no local services" stands for *standard* protocols only — the camera
  likely listens for the **proprietary** p4p LAN-search broadcast, which our
  probe never sent. Correction of emphasis, not of fact.
- Auth will need the device **UID** + a view account/password
  (`CLI_WRONG_VIEWACCPWD`).

**Next experiment:**
1. Capture the UBox app doing a **LAN search** with phone **and** camera on the
   same LAN → recover the discovery UDP port + request/response bytes.
2. Replay that probe from `probe_camera.py`; confirm the camera answers.
3. Then attempt a LAN session and the `send_ioctrl` PTZ opcodes.

---

## 2026-07-22 — First idle capture: platform identified as UBIA

**Conditions:** MikroTik sniffer→file, filtered to `192.168.88.113`. Camera
online, no deliberate user interaction ("idle"). 341 s, 10,168 packets,
`captures/rbx-idle.pcap`.

**Commands:**
```
scripts/summarize_pcap.py captures/rbx-idle.pcap --camera-ip 192.168.88.113
scripts/udp_flow_report.py captures/rbx-idle.pcap --min-packets 8
tshark -r ... -Y 'tls.handshake' | wc -l      # -> 0
tshark -r ... -Y 'http.request'               # -> none
```

**Observed (facts):**
- **Vendor cloud is `ubianet.com` → the UBIA platform** (matches UBox app).
  Resolves a pool `m1..m8.ubianet.com` + `portal.us.ubianet.com`, hosted on
  Tencent + Alibaba Cloud.
- **Three channels**, all proprietary:
  - **UDP 10240** → rendezvous pool; identical 16-byte header sent 6× to
    several `m*` servers (registration/lookup).
  - **UDP 20001** → 4 media servers; 2 pkts / 548 B every **~30 s**.
  - **TCP 443** → same 4 media servers; persistent connections, 20–37 B
    messages every ~6–10 s. **Zero TLS handshakes** → *not* HTTPS.
- **TCP 80 traffic is not HTTP** (`http.request` = 0): bare TCP connects to
  Akamai/CloudFront = reachability tests.
- **Media upload burst at t≈190–200 s:** 242 pkts / 312 KB in ~10 s (+24 KB),
  1320 B packets, camera→`170.101.97.156:20001`, **entropy 7.5 bits/byte**.
  Steady state on that flow is otherwise only the 30 s keepalive.
- **DNS flood = 86% of the capture** (8,768 pkts): 8 well-known domains
  (~1,040 queries each). Bursty — silent t=30–150 s, then ~34 queries/s during
  t=180–270 s, correlating with the upload.
- Header fingerprints share the constant `d8d2254d498d` in **both directions
  and both ports** → likely obfuscated device UID. Control entropy 4.87–6.34
  (structured/obfuscated), media 7.5 (encrypted/compressed).

**Interpretation:**
- Platform = **UBIA cloud-brokered P2P**. Tag: **Confirmed.**
- Camera maintains a **persistent outbound control connection** (answers
  CLAUDE.md question 12: **yes**). Tag: **Confirmed.**
- Camera **uploaded media to the cloud with no user interaction**. Tag:
  **Strongly indicated** (likely a motion-triggered event clip).
- Control plane is obfuscated but **low-entropy → plausibly reversible**;
  media is encrypted/compressed and will be the hard part. Tag: **Possible.**
- No STUN/TURN/QUIC/MQTT/RTP/mDNS/SSDP observed at all. Tag: **Confirmed**
  (for this capture).

**Capture artifact (important):** the MikroTik sniffer recorded **each frame
twice** (ingress+egress); `editcap -d` reduces 10,168 → 7,197 packets. Real
counts/bytes are ~half those reported. Qualitative findings unaffected.
Procedure updated to dedupe / pin `filter-interface`.

**Tooling fix:** `high_bandwidth_flows()` was flagging 4-packet DHCP and
12-packet TCP handshakes as "likely video" because a sub-second duration
inflates the byte-rate. Now the rate test requires ≥1 s and ≥20 packets; only
the genuine 336 KB media flow is flagged. +2 regression tests (25 total).

**Next experiment:**
1. **Live-view capture** with the phone on a *different* AP/VLAN than the
   camera (so any direct phone↔camera P2P crosses the tap), then
   `compare_sessions.py idle=... live=...` to isolate session setup + video.
2. Repeat idle capture to test whether the obfuscation mask is **static**.

---

## 2026-07-21 — First live probe of the camera

**Conditions:** Camera online & awake (UBox not necessarily open). Camera at
`192.168.88.113` on the MikroTik `192.168.88.0/24` LAN. No captures yet.

**Command:** `python scripts/probe_camera.py 192.168.88.113`

**Observed (facts):**
- Camera responds to ICMP ping and is in the ARP table → **awake**.
- MAC OUI `84:1D:E8` → **CJ intelligent technology LTD.** (resolved via
  tshark manufacturer DB) — a Chinese IoT/camera ODM.
- **Zero open TCP ports** from the curated camera/RTSP/ONVIF/HTTP list — now
  confirmed *while awake*, so the earlier nmap result was not just "asleep".
- **No RTSP** on 554/8554.
- **ONVIF WS-Discovery: camera silent** (0 replies from the camera).
- **SSDP/UPnP: camera silent.** 10 replies came from *other* LAN devices
  (`192.168.88.37` = a WPS/Wi-Fi-Alliance WFADevice, likely the router/AP;
  `192.168.88.76` = an Android/Chromecast device) — none from the camera.

**Interpretation:**
- The camera exposes **no local listening services or discovery responders**
  of any conventional kind. Tag: **Confirmed** (for TCP + RTSP + ONVIF-WSD +
  SSDP, camera awake).
- Consistent with an **outbound-only, cloud-assisted P2P** design; local
  ONVIF/RTSP/Generic-Camera integration paths are effectively ruled out
  *unless* firmware analysis reveals a disabled/hidden server. Tag: **Strongly
  indicated.**

**Tooling fix (this session):** `probe_camera.py` now attributes WS-Discovery/
SSDP replies to the camera vs other LAN devices, and only counts the camera's
own replies toward "awake". (Previously other devices' SSDP replies were
listed ambiguously.)

**Next experiment (smallest first):**
1. Static DHCP lease for `192.168.88.113` on the MikroTik.
2. Passive capture of **boot** and **idle**, then `summarize_pcap.py` +
   `extract_dns.py` to enumerate the vendor DNS names / cloud endpoints and
   the steady-state outbound flows (expect a persistent keepalive).

---

## 2026-07-21 — Project bootstrap & analysis tooling

**Conditions:** macOS dev host. No captures taken yet. Camera not yet probed
in this session.

**Actions**
- Initialized repo (git, `.gitignore` excluding pcaps/apk/firmware/secrets).
- Decision: PCAP analysis built on **tshark subprocess** backend (leverages
  Wireshark dissectors for STUN/TURN/RTP/QUIC/DTLS/mDNS/SSDP). Alternatives
  considered: scapy, dpkt, hybrid. Rationale: the camera almost certainly
  speaks a P2P protocol Wireshark already dissects, so hand-rolling parsers
  would be wasted effort.
- Installed `tshark` 4.6.7 via Homebrew; created `.venv` with `pytest`.
- Built read-only tools: `summarize_pcap.py`, `compare_sessions.py`,
  `extract_dns.py`, `udp_flow_report.py`, plus the non-destructive
  `probe_camera.py`. Shared logic in `scripts/pcaptools/`.
- 23 unit/integration tests pass (incl. a real tshark run on a hand-built
  pcap). Verified all four analysis CLIs against synthetic idle/live captures:
  correctly isolated a high-bandwidth "video" flow, a keepalive flow, unique
  per-scenario DNS names, and a payload sequence-counter field.

**Prior finding carried over (from CLAUDE.md):**
- Full TCP scan (`nmap -Pn -p-`) and `-sV -A` found **no listening TCP
  services** on the camera. Tag: **Confirmed** (per prior work), but note the
  camera may have been asleep — re-test while awake.

**Interpretation**
- No TCP servers is consistent with an outbound-only, cloud-assisted P2P
  design. Tag: **Possible** (needs capture evidence).

**Next experiment (smallest first)**
1. Assign the camera a static DHCP lease; record its IP + MAC.
2. Wake camera, run `probe_camera.py <ip>` — confirm awake, re-check for any
   transient local ports, WS-Discovery/SSDP responses.
3. Capture **boot** and **idle** scenarios; run `summarize_pcap.py` and
   `extract_dns.py` to enumerate DNS names and steady-state flows.

---

## Template for new entries

```
## YYYY-MM-DD — <short title>

**Conditions:** <online/blocked, camera awake?, capture file(s)>
**Command(s):** <exact commands run>
**Observed:** <facts only>
**Interpretation:** <hypotheses, each tagged Confirmed/Strongly indicated/Possible/Unknown>
**Next experiment:** <smallest test that distinguishes competing hypotheses>
```
