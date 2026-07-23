# Bridge Design — RBX-S73 → Home Assistant

Architecture decisions (2026-07-23) and the plan for the local bridge daemon.

## Decision

- **Output:** the bridge exposes an **H.264 RTSP** stream via **go2rtc/MediaMTX**;
  Home Assistant consumes it through the Generic Camera / go2rtc integration,
  and Frigate can use the same stream. (A native custom HA component with PTZ
  entities can be layered on later — not required for first light.)
- **Deployment:** a small **Docker** daemon on a **Linux server with an interface
  on the camera's isolated VLAN**. Config via env/secrets; no cloud dependency.

## Target architecture

```
RBX-S73 camera  (isolated VLAN)
     │  p4p: LAN-search(32762) → preconnect/PUNCH2LAN → KCP → lanstreamreq
     ▼
p4p bridge daemon (Docker, on camera VLAN)      ← this repo's p4p/ package
     │  H.264 elementary stream
     ▼
go2rtc / MediaMTX  ── RTSP / WebRTC ──►  Home Assistant  /  Frigate
```

## Bridge daemon responsibilities (Phase 3)

- Wrap the `p4p` client: discover → connect → `start_video()` → yield H.264.
- Feed frames to go2rtc/MediaMTX (e.g. an RTSP/`exec` source, or push).
- Per CLAUDE.md proxy requirements: **env/secrets config** (UID, credential,
  camera IP), **structured logging**, **auto-reconnect** (incl. the LAN-search
  radio-warmup retry), **health endpoint**, optional PTZ control surface.
- Map PTZ/commands to `send_ioctrl` + the `AVIOCTRLDEFs` opcodes (recovered).

### Config (draft)
```
RBX_CAMERA_IP=192.168.x.y
RBX_UID=<20-char UID>          # secret (env/secret file, never committed)
RBX_CREDENTIAL=<from LanSearchInfo, or the app account/password>
RBX_STREAM=main|sub            # SETSTREAMCTRL streamindex
```

## VLAN lockdown (Phase 4)

Once RTSP works, isolate the camera. Firewall policy (from CLAUDE.md):
```
Allow  bridge_host  → camera      (p4p: UDP 32762 + the session ports)
Allow  camera       → bridge_host (return traffic)
Allow  camera       → local DNS   (only if the camera needs it locally)
Allow  camera       → local NTP   (only if needed)
Block  camera       → all WAN
Block  camera       → other VLANs
Block  other LAN    → camera      (only the bridge may reach it)
```
- Static DHCP lease for the camera.
- The bridge host straddles the camera VLAN and the HA/NVR network (or HA/
  go2rtc reaches the bridge over a permitted path).
- **Do not apply the permanent WAN block until the bridge is proven** — blocking
  earlier is fine for testing but confirm local session survives WAN loss
  (expected: yes, since discovery+session are LAN-only).

## Open decision for Phase 2b

- **KCP library:** wrap an existing KCP (stock `ikcp`) rather than reimplement.
  Options: a pure-Python `ikcp` port (vendored, full control of the config
  params the SDK uses — `nodelay/interval/window`) vs a C-binding package. To be
  chosen when we implement the session. Conv id = the client `randomID`.
