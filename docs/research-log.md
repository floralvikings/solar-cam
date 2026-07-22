# Research Log — RBX-S73

Chronological log of what was done, what was observed, and what it means.
Newest entries at the top. Keep **observed facts** separate from
**hypotheses**, and tag conclusions: **Confirmed / Strongly indicated /
Possible / Unknown**.

> Redaction note: full MAC / device UID are kept out of committed docs
> (recorded only in the operator's local notes). OUI + RFC1918 IPs are fine.

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
