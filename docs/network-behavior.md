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
| Idle | | | | | | | |
| App startup | | | | | | | |
| Live view open | | | | | | | |
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
- mDNS: _TBD_
- SSDP / UPnP: _TBD_
- WS-Discovery (ONVIF): _TBD_
- ARP / DHCP / NTP: _TBD_

Run `scripts/probe_camera.py <ip>` (awake) to actively check the discovery
protocols and any transient local ports.
