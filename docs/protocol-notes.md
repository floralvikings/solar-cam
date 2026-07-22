# Protocol Notes — RBX-S73

Reverse-engineering notes on the wire protocol(s). Populate from
`scripts/udp_flow_report.py` and manual Wireshark inspection.

## Working hypothesis
Cloud-assisted P2P camera platform (like many budget cams): app + camera each
keep an outbound control channel to a vendor cloud; the cloud brokers a P2P
session (STUN/relay); video/control then flow over a **proprietary UDP**
protocol, possibly relayed. Tag: **Possible** — no evidence yet.

Common platforms to compare against once we have bytes: **TUTK/Kalay
(PPPP/PPCS)**, **PPStrong / iLnk**, **Gwelltimes / iCSee (XM)**, **Tuya**,
**Ayla**. Look for characteristic magic bytes / handshakes.

## Channels (fill in)
| Channel | Direction | Transport | Remote | Port | Encrypted? | Notes |
|---------|-----------|-----------|--------|------|-----------|-------|
| Control / keepalive | | | | | | |
| Signaling (session setup) | | | | | | |
| Video | | | | | | |
| Audio | | | | | | |

## Per-flow fingerprints
For each candidate UDP flow, paste the `udp_flow_report.py` output:
- Payload length distribution
- Common header bytes (magic)
- Byte entropy (low → structured/plaintext; ~8 → encrypted/compressed)
- Sequence-counter field (offset/width/endian)
- Directional asymmetry (video is usually camera→peer heavy)

```
(paste udp_flow_report.py output here)
```

## Command IDs (pan/tilt/wake/live/playback)
Compare `compare_sessions.py` output across single-action captures to isolate
the request packets, then diff payloads to locate the command opcode.

| Action | Distinguishing flow | Payload delta / opcode | Confidence |
|--------|--------------------|------------------------|------------|
| Wake | | | |
| Live view start | | | |
| Live view stop | | | |
| Pan | | | |
| Tilt | | | |
| SD playback | | | |

## Encryption / key derivation
- Is video encrypted? (entropy test) — **Unknown**
- Handshake / key exchange observed? — **Unknown**
- Keys derived from device UID / password? (check UBox APK) — **Unknown**
