# Network Behavior — RBX-S73

Observed network behavior per scenario. Populate from captures using
`scripts/summarize_pcap.py` and `scripts/compare_sessions.py`.

## Known so far
- Camera IP `192.168.88.113`, MAC OUI `84:1D:E8` (CJ intelligent technology
  LTD.), on MikroTik `192.168.88.0/24`. — **Confirmed** (2026-07-21 probe).
- Full TCP port scan found **no listening services** (`nmap -Pn -p-`,
  `nmap -Pn -sV -A`). Re-confirmed via `probe_camera.py` **while awake**
  (ping+ARP up, targeted TCP list all closed). Tag: **Confirmed.**
- **No RTSP** (554/8554), **no ONVIF** (WS-Discovery silent), **no SSDP/UPnP**
  from the camera. Tag: **Confirmed** (camera awake, 2026-07-21).
- ⇒ Local ONVIF / Generic-RTSP / SSDP integration paths ruled out barring a
  hidden server in firmware. Focus shifts to passive capture of outbound P2P.

## Scenario matrix (fill from captures)

| Scenario | Capture file | DNS names | Remote endpoints | L4/proto | Direct phone↔cam? | Via relay? | Notes |
|----------|--------------|-----------|------------------|----------|-------------------|-----------|-------|
| Boot | | | | | | | |
| Idle | `rbx-idle.pcap` | `m1..m8.ubianet.com`, `portal.us.ubianet.com`, NTP, 8 connectivity-check domains | rendezvous pool (UDP 10240); 4 media servers `170.101.97.156`, `149.56.108.231`, `43.173.75.192`, `45.125.216.146` (TCP 443 + UDP 20001) | proprietary UDP + proprietary TCP/443 (**not TLS**) | n/a (phone idle) | n/a | 30s UDP keepalive; 6–10s TCP/443 heartbeat; **336 KB media burst at t≈190s**; DNS flood = 86% of capture |
| App startup | | | | | | | |
| Live view open | `rbx-live.pcap` | (phone) `m*.ubianet.com`, media servers | phone→cloud lookup/session only; **phone↔camera direct = 0 at router** | P4P over UDP, direct P2P bridged in AP | **Yes (direct)** | No | Video L2-bridged in AP, invisible to router; phone LAN-searches on 32762 first |
| Live view close | | | | | | | |
| Pan | | | | | | | |
| Tilt | | | | | | | |
| Two-way audio | | | | | | | |
| Motion trigger | | | | | | | |
| SD playback | | | | | | | |
| WAN blocked (camera) | | | | | | | |

## Internet-blocking results (Tests A–D from CLAUDE.md)

| Feature | A: all online | B: cam WAN blocked | C: phone WAN blocked | D: both blocked |
|---------|---------------|--------------------|----------------------|-----------------|
| Device status | | | | |
| Live view | | | | |
| Pan/tilt | | | | |
| Audio | | | | |
| Motion notif | | | | |
| SD playback | | | | |

Interpretation goes in `cloud-dependencies.md`.

## Discovery protocols observed
Idle capture (`rbx-idle.pcap`) — the camera emits **no** local discovery:
- mDNS: **none** — **Confirmed**
- SSDP / UPnP: **none from the camera** — **Confirmed**
- WS-Discovery (ONVIF): **none** — **Confirmed**
- STUN / TURN / QUIC / DTLS / MQTT / RTP / RTCP: **none observed** — **Confirmed**
- ARP / DHCP: yes (DHCP Offer/ACK from `192.168.88.1` captured at start)
- NTP: yes (`pool.ntp.org`, `hk.ntp.org.cn`, `de.ntp.org.cn`, `uk.ntp.pool.org`)

⇒ The camera is **outbound-only to the UBIA cloud**. Nothing on the LAN can
discover or address it. See `protocol-notes.md` and `cloud-dependencies.md`.

Run `scripts/probe_camera.py <ip>` (awake) to actively check the discovery
protocols and any transient local ports.
