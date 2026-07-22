# Cloud Dependencies — RBX-S73

Goal: determine exactly what the vendor cloud is needed for, so WAN can be
blocked without breaking local use. Conclusions here drive the final firewall
policy in `CLAUDE.md` → Network Lockdown Goal.

## The question
Is the cloud used for: **discovery**, **authentication**, **signaling/session
setup**, **relay of media**, or **all communication**? The Internet-blocking
matrix (Tests A–D) plus captures answer this.

## Evidence ledger

| Claim | Evidence (capture/test) | Tag |
|-------|-------------------------|-----|
| Camera holds a persistent outbound control connection | | Unknown |
| Cloud performs authentication only | | Unknown |
| Cloud performs P2P signaling (hands out relay/peer) | | Unknown |
| Media is relayed through cloud (not direct P2P) | | Unknown |
| Media travels directly phone↔camera on LAN | | Unknown |
| LAN-only live view works after cloud init | | Unknown |
| LAN-only works from cold (no cloud at all) | | Unknown |

## Vendor endpoints (redact public IPs before publishing)
From `extract_dns.py` / SNI:

| Hostname | Resolved IP(s) | Purpose (inferred) |
|----------|----------------|--------------------|
| | | |

## Provisional lockdown readiness
- [ ] Cloud role fully characterized
- [ ] Confirmed which features survive camera-WAN-block (Test B)
- [ ] Local DNS / NTP needs identified
- [ ] Safe to apply permanent WAN block

> Do **not** apply permanent WAN-block rules until the exact dependency is
> documented — blocking too early interferes with capture analysis.
