# Research Log — RBX-S73

Chronological log of what was done, what was observed, and what it means.
Newest entries at the top. Keep **observed facts** separate from
**hypotheses**, and tag conclusions: **Confirmed / Strongly indicated /
Possible / Unknown**.

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
