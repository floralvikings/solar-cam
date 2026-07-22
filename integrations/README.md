# Integrations

Config for exposing the RBX-S73 to Home Assistant, **once local access is
proven**. Preferred target order (from `CLAUDE.md`):

1. Native **ONVIF** integration (if the camera turns out to speak ONVIF)
2. **Generic Camera** integration (if a plain RTSP/MJPEG URL exists)
3. **go2rtc** restream (`integrations/go2rtc/`)
4. **Frigate** camera input (`integrations/frigate/`)
5. Custom Home Assistant integration
6. Local **bridge daemon** translating the proprietary protocol → RTSP, fed
   into go2rtc/MediaMTX

Target pipeline if a bridge is needed:

```
RBX-S73 ──proprietary P2P──▶ bridge daemon ──▶ go2rtc / MediaMTX ──RTSP/WebRTC──▶ Home Assistant / Frigate
```

Subdirectories (`go2rtc/`, `home-assistant/`, `frigate/`) hold the actual
config files as each target is validated. Empty until Phase 1 (protocol
analysis) yields a working local stream.
