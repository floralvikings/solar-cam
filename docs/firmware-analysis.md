# Firmware Analysis — RBX-S73

Only analyze firmware obtained legally via the vendor's own update mechanism.
Back up before modifying anything. Firmware images are **git-ignored**
(`firmware/`).

## OTA capture
Watch for update-check requests during boot / app startup / settings access.

| Field | Value |
|-------|-------|
| Firmware version | _TBD_ |
| Update-check endpoint | _TBD_ |
| Download URL | _TBD_ |
| File size | _TBD_ |
| Hash | _TBD_ |
| Signature info | _TBD_ |
| Compression | _TBD_ |
| Encrypted? | _TBD_ |

## Extraction (once an image is legally obtained)
```bash
file firmware/image.bin
binwalk firmware/image.bin
binwalk -eM firmware/image.bin
strings firmware/image.bin | less
```

## What to look for
Streaming/servers: `rtsp onvif live555 gstreamer ffmpeg boa lighttpd nginx`
System: `busybox telnetd dropbear udhcp wpa_supplicant`
P2P/cloud: `mqtt stun turn p2p` and ports `554 8554`

## Findings
- SoC vendor: _TBD_
- Kernel version: _TBD_
- Filesystem layout: _TBD_
- Init scripts / disabled daemons: _TBD_
- Debug interfaces (telnet/ssh): _TBD_
- Hard-coded credentials / public keys: _TBD_
- Update verification logic: _TBD_
- Any RTSP/ONVIF server present but disabled: _TBD_ ← **key question**
