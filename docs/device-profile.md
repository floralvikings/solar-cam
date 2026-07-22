# Device Profile — SEHMUA RBX-S73

Facts about the physical device and account. Fill in as discovered. Tag each
line **Confirmed / Strongly indicated / Possible / Unknown**.

## Identity
- Manufacturer: SEHMUA — **Confirmed**
- Model: RBX-S73 — **Confirmed**
- Type: solar/battery pan-tilt Wi-Fi camera — **Confirmed**
- Mobile app: UBox — **Confirmed**
- Firmware version: _TBD_ — **Unknown**
- Hardware revision / PCB markings: _TBD_ — **Unknown**
- SoC / Wi-Fi chip: _TBD_ — **Unknown** (see `hardware-notes.md`); MAC OUI
  vendor is a lead (Chinese IoT/camera ODM).

## Network identity (redact before publishing)
- MAC address: `84:1d:e8:xx:xx:xx` (full value in operator's local notes) —
  **Confirmed**
- OUI / vendor from MAC: `84:1D:E8` → **CJ intelligent technology LTD.** —
  **Confirmed** (tshark manuf DB)
- Current IP: `192.168.88.113` (RFC1918) — **Confirmed**; static lease _TBD_
- Device UID / serial (as used by UBox/cloud): _TBD_ — **Unknown**

## Capabilities to characterize
- [ ] Live video
- [ ] Pan / tilt
- [ ] Two-way audio
- [ ] Motion detection + notifications
- [ ] microSD recording + playback
- [ ] Sleep/wake behavior (does the radio drop when idle?)

## Storage
- microSD: present — **Confirmed** (per spec)
- Vendor cloud storage: optional — **Confirmed** (per spec)

## Power / sleep
- Battery + solar; **may sleep when idle** — **Strongly indicated** (per spec).
  Implication: wake the camera immediately before any scan/capture.
