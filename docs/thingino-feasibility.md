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

**A full thingino replacement — thingino's own kernel — is closed.** Confirmed
offline from the module itself:

```
author=Hisilicon Wifi Team      depends=mmc_core,jzmmc
vermagic=3.10.14-Archon preempt mod_unload MIPS32_R1 32BIT
cfg80211 / ieee80211 / wiphy imports: 0
```

`hichannel.ko` imports **zero** cfg80211 symbols, so it registers no wiphy and
`wpa_supplicant` cannot drive it (there is no `wpa_supplicant` on the device
either). The `[cfg80211]` kthread is simply built into the kernel and unused by
this driver. Association goes through a private vendor interface. A thingino
kernel therefore means no Wi-Fi, and no way back in.

## ✅ But the hybrid **is** viable — vendor kernel + our own userland

Proven live 2026-08-07:

| Question | Answer |
|---|---|
| Can the watchdog be stopped? | **Yes** — `touch /tmp/stopWdg`. The vendor's own escape hatch (`stop watchdog by file`, `wdt_disable ok` in `ubia_watchdog`). |
| Does Wi-Fi need `ubia_t23`? | **No.** With `ubia_t23` killed, the shell stayed reachable **224 s+** with no reboot. |
| Is the ISP freed? | **Yes**, once `ubia_t23` exits. |
| Is it fail-safe? | **Yes** — `/tmp` is tmpfs, so any reboot re-arms the watchdog automatically. |

Without the stop-file, killing `ubia_t23` reboots the box in ~10 s
(`ubia_watchdog` monitors a heartbeat timestamp — `secondProcLastTime` /
`secTimeOutMs` — and resets via `/dev/watchdog` or `HI_HAL_MCUHOST_JUST_RESET`).

So the platform is: **vendor kernel + vendor rootfs** (keeps `hichannel` Wi-Fi,
`tx-isp`, motors) **+ our own `/system`**, which we already flash safely over OTA.

### Dev loop that needs no flashing at all
busybox has **`tftp`**, so binaries can be pushed to `/tmp` and run directly:

```sh
tftp -g -r prudynt -l /tmp/prudynt <host>     # on the camera
touch /tmp/stopWdg && killall ubia_t23 && /tmp/prudynt
```
Only bake into `/system` once something works. Reboot undoes everything.

### The one remaining unknown: IMP ↔ tx-isp pairing
Both vendor binaries **statically link** the Ingenic SDK, so there is no
`libimp.so` to reuse. A streamer (e.g. thingino's `prudynt`) needs its own
`libimp` for T23, and that userspace must match the **vendor's built-in
`tx-isp` (`H20240430a`)** — thingino ships kernel+libimp as matched pairs, so
version skew is the real risk here, not the flashing.

Also needed: a MIPS **C** cross-compiler. Only binutils is installed locally
(enough for `rbxsend`, not for `prudynt`).

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
