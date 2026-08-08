# thingino / OpenIPC feasibility on the RBX-S73

Assessed 2026-08-07 from a **root shell on the running camera** (see
`firmware-analysis.md` for how that was obtained). Raw inventory:
`captures/hwinfo.txt` (gitignored).

## Hardware, as reported by the device itself

| Item | Value | Source |
|---|---|---|
| SoC | `system type: Indus_T23_QFN`, `Hardware: isvp` | `/proc/cpuinfo` |
| CPU | Ingenic XBurst, **mips32r1**, 1391 BogoMIPS, 1 core | `/proc/cpuinfo` |
| Kernel | `3.10.14-Archon` (built 2025-07-11) | `uname -a` |
| Sensor | **`cv2003`**, i2c0 @ **0x35**, driver `H20240510a` | `dmesg` |
| ISP | `tx-isp` `H20240430a / Z20240103r` | `dmesg` |
| Wi-Fi | **SDIO card on mmc1, driven by `hichannel.ko`** (53632 B) | `lsmod`, `dmesg` |
| Flash | SPI NOR via `jz_sfc` | `dmesg` |
| Motors | `motor.ko` (also `newmcu-motor.ko` present) | `lsmod` |
| Modules | `motor, alarm_led, hichannel, vfat, fat, mmc_block, jzmmc, mmc_core, squashfs, jffs2, jz_sfc` | `lsmod` |

## The blockers, in order of severity

### 1. Wi-Fi is a proprietary SDIO part — **decisive**
`rcS` loads `/system/hichannel.ko`; `dmesg` shows `mmc1: new SDIO card at
address 0001` then `[WARN]:52:wlan drv insmod SUCCESSFULLY`. `esp32_sdio.ko`
ships but is **never loaded** — the earlier assumption that this is an ESP32 was
wrong. The `hisi_hcc_tx`/`hisi_hcc_rx` kernel threads and the
`ubia_ota_update_hi3861` OTA branch point at a **HiSilicon Hi3861-class** module.

thingino builds its own kernel, so a module compiled for `3.10.14-Archon` will
not load (vermagic/symbol CRC mismatch), and thingino has no in-tree driver for
this part. **A thingino flash therefore yields a camera with no network — which
is also the only route back in.** Recovery would be chip-off.

*Mitigating nuance:* `/sys/class/ieee80211` exists and a `[cfg80211]` kthread is
running, so `hichannel` does register with cfg80211. A **vendor-kernel +
thingino-userland** hybrid is therefore more plausible than a straight port —
but association may still go through the vendor app's private API rather than
`wpa_supplicant`, which is unverified.

### 2. The sensor is unusual
`cv2003` is not one of thingino's common targets (mostly `sc*`, `gc*`, `jx*`).
Keeping the vendor kernel keeps `tx-isp` + the `cv2003` driver; porting to a
thingino kernel means porting the sensor driver too.

### 3. No shared IMP SDK to build against
`ubia_t23` NEEDs only `libpthread/librt/libdl/libstdc++/libm/libgcc_s/libc` —
there is **no `libimp.so` on the device** — yet it contains **524 `IMP_*`
symbols**. The Ingenic SDK is **statically linked into the vendor binary**. So
"just run `prudynt` on the stock OS" does not work as-is: we would have to supply
our own T23 `libimp`, and the ISP is in any case held exclusively by `ubia_t23`
while it runs.

### 4. The camera cold-boots constantly
Observed `uptime` of ~22 s repeatedly, and `telnetd` started from our hook
disappears within minutes. This is a solar/battery camera **power-cycling on
sleep/wake**, not a watchdog kill. Any always-on streaming design has to defeat
the vendor's sleep logic first.

## Verdict

**A full thingino replacement on the primary camera is not advisable.** The
Wi-Fi driver alone makes an unreachable-camera outcome likely, and the only
recovery is desoldering.

## Sane paths forward

1. **Do firmware work on the *spare*, never the primary.** The spare has already
   been opened once and its flash read off-board, so a brick costs a re-clip
   rather than the working camera. This is the single biggest risk reduction
   available and should precede any thingino attempt.
2. **Bridge the existing local H.264 to RTSP on the host** (`go2rtc`/MediaMTX +
   `scripts/capture_h264.py`). Achieves the actual project goal — a real RTSP
   camera in Home Assistant — with **zero device risk**, since it changes nothing
   on the camera.
3. **Use the root shell for what only it can do**: read/modify `tag` settings,
   investigate the sleep behaviour, and dump partitions. `/dev/mtd11` exposes the
   whole flash, so backups are now cheap.
4. **Research track, if desired:** determine whether `hichannel` can be driven by
   `wpa_supplicant` over cfg80211. If yes, a vendor-kernel + custom-userland
   hybrid becomes realistic; if no, thingino on this model is effectively closed
   until someone writes a driver.
