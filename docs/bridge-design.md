# Bridge Design — RBX-S73 → Home Assistant

Architecture decisions (2026-07-23) and the plan for the local bridge daemon.

## Decision (updated 2026-07-23 — run on the HA box)

- **Deployment (revised):** a **HACS custom integration** that runs the
  **pure-Python `p4p` client + KCP receiver ON the Home Assistant device** — no
  separate daemon. The whole stack (`p4p.client.stream_h264`) is pure Python
  specifically so it installs and runs inside HA. User "adds the HACS repo" and
  configures the camera in the HA UI.
- **Output:** the integration hands the decoded **H.264** to HA's bundled
  **go2rtc** (HA ships go2rtc), which restreams as RTSP/WebRTC/HLS to the
  frontend and to Frigate. (Original plan — a standalone Docker daemon on the
  camera VLAN — remains a valid alternative if HA can't reach the camera VLAN.)

### HACS integration shape (Phase 3, to build)
```
custom_components/rbx_s73/
  __init__.py, manifest.json (hacs.json at repo root)
  config_flow.py     # UI: camera IP + UID; password auto-discovered from LanSearchInfo
  camera.py          # Camera entity; stream via HA stream/go2rtc
  coordinator.py     # runs p4p.client.stream_h264 in an executor/async task
```
- Config: camera IP + UID (the view password is auto-discovered from the
  camera's LanSearchInfo, so the user need not enter it).
- Feed H.264 to go2rtc (e.g. an `exec:` source running `scripts/capture_h264.py`,
  or push frames into HA's stream worker).
- Constraint: **one session per camera** — the integration owns the session, so
  don't run UBox live view against the same camera simultaneously.
- Later: PTZ via `send_ioctrl` + the `AVIOCTRLDEFs` opcodes as HA buttons/services.

Reference client already built: `p4p.client.stream_h264` + `scripts/capture_h264.py`
(verified: 640x360 H.264 decoded by ffmpeg, cloud-free).

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

## Multi-camera (design requirement)

More RBX-S73 cameras may be added later, so the bridge is **multi-camera from
the start**: a list of camera configs (each with its own UID/credential/IP/
stream), one independent `p4p` session per camera, each fronted as its own
go2rtc stream (e.g. `rbx-<name>`). Discovery is per-UID (LAN-search names the
UID), so multiple cameras coexist on the same VLAN without collision. The daemon
supervises N sessions with independent reconnect/health.

```
cameras: [ {name, uid(secret), ip, stream}, ... ]  →  N p4p sessions  →  N go2rtc streams
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
