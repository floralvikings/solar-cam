# Cloud Dependencies — RBX-S73

Goal: determine exactly what the vendor cloud is needed for, so WAN can be
blocked without breaking local use. Conclusions here drive the final firewall
policy in `CLAUDE.md` → Network Lockdown Goal.

Evidence base: idle capture `rbx-idle.pcap` (2026-07-22, 341 s).

## Platform: **UBIA** (`ubianet.com`) — **Confirmed**

## Vendor endpoints observed

### Rendezvous / lookup pool (UDP 10240)
The camera resolves an 8-server pool and sends an identical registration/lookup
packet to several of them.

| Hostname | Resolved IP | Hoster |
|----------|-------------|--------|
| `m1.ubianet.com` | 175.178.248.245 | Tencent Cloud |
| `m2.ubianet.com` | 121.199.12.37 | Alibaba Cloud |
| `m3.ubianet.com` | 43.153.110.207 | Tencent Cloud |
| `m4.ubianet.com` | 8.208.11.50 | Alibaba Cloud |
| `m5.ubianet.com` | 43.134.10.68 | Tencent Cloud |
| `m6.ubianet.com` | 43.157.31.112 | Tencent Cloud |
| `m7.ubianet.com` | *(no answer captured)* | |
| `m8.ubianet.com` | *(no answer captured)* | |
| `portal.us.ubianet.com` | *(no answer captured)* | US portal/API |

Also contacted on UDP 10240: `198.11.182.160`, `47.91.95.131`,
`120.25.212.231`, `47.89.179.27` (Alibaba ranges).

### Media / relay servers (TCP 443 **and** UDP 20001)
Four servers, contacted on **both** transports simultaneously and held open:

`170.101.97.156` · `149.56.108.231` · `43.173.75.192` · `45.125.216.146`

`170.101.97.156` received the ~336 KB media burst.

### Non-vendor traffic
- **Connectivity checks** (not cloud dependency): DNS + TCP/80 to
  microsoft/amazon/qq/apple/baidu/google/jd/taobao CDNs (Akamai, CloudFront).
- **NTP**: `pool.ntp.org` and friends, `hk.ntp.org.cn`, `de.ntp.org.cn`.

## Evidence ledger

| Claim | Evidence | Tag |
|-------|----------|-----|
| Camera holds a **persistent outbound control connection** | TCP 443 to 4 servers, 20–37 B heartbeats every ~6–10 s; UDP 20001 keepalive every ~30 s | **Confirmed** |
| Camera registers with a **rendezvous server pool** | Identical 16-B header sent 6× to multiple `m*.ubianet.com` on UDP 10240 | **Strongly indicated** |
| Camera **uploads media to the cloud unprompted** | 336 KB burst, entropy 7.5, camera→`170.101.97.156:20001` at t≈190 s while "idle" | **Strongly indicated** |
| Control traffic on 443 is **not TLS** | 0 TLS handshakes; decoded as plaintext `uid=`/`hostalive=`/`iotalive=` heartbeats | **Confirmed** |
| Cloud performs P2P signaling (hands out peer/relay) | Decoded `0x1101/0x1102` session-connect + `0x1105/0x1106` peer-address exchange | **Confirmed** |
| Cloud is a **rendezvous/hole-punch broker** | `0x1105` carries phone LAN `192.168.88.111:34755`; `0x1106` carries camera LAN `192.168.88.113:33900` | **Strongly indicated** |
| Media relayed via cloud vs direct P2P | Live view: **no** media flow through the router at all; event-clip upload (`0x140a`) is a separate cloud path | **Confirmed** (live view is direct, not relayed) |
| Media travels directly phone↔camera on LAN | Live capture: 0 phone↔camera pkts at the router + 0 video volume, yet live view worked → AV is L2-bridged in the AP | **Confirmed** |
| LAN-only live view works after cloud init | Phone located camera via LAN-search (32762), not cloud; cloud responses omit the camera LAN addr | **Confirmed** (on shared LAN) |
| LAN-only live view works after cloud init | Needs Test B | Unknown |
| LAN-only works from cold (no cloud at all) | Needs Test D | Unknown |

## Privacy / security notes

1. Even with no user interaction, the camera **uploaded ~336 KB of
   encrypted/compressed media to a cloud server** during a 5.7-minute idle
   capture, and generated ~8,700 DNS queries.
2. **Unauthenticated LAN credential disclosure (Confirmed, 2026-07-23):** the
   camera answers a proprietary UDP LAN-search (port 32762) from *any* host and
   returns the device UID, account username, and a credential string. The
   "encryption" is a fixed obfuscation with a key hardcoded in the app
   (`ubia_crypto.py`), so this is effectively cleartext to anyone on the LAN.
   Mitigation for the final lockdown: isolate the camera on its own VLAN and
   block unsolicited LAN clients → camera (already in the lockdown goal).

## Provisional lockdown readiness
- [x] Vendor endpoints enumerated (`*.ubianet.com` pool + 4 media servers)
- [x] Persistent control channel identified (TCP 443 + UDP 20001)
- [ ] Cloud role in **session setup** characterized (needs live-view capture)
- [ ] Confirmed which features survive camera-WAN-block (Test B)
- [ ] Local DNS / NTP needs identified
- [ ] Safe to apply permanent WAN block

> Do **not** apply permanent WAN-block rules yet — blocking now would prevent
> capturing the live-view/pan session setup we still need.
