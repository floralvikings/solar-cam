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

## 🎯 ANSWERED: thingino's libimp **works** against the vendor tx-isp

Tested live 2026-08-07 with `prudynt-T23-static` (from `gtxaspec/prudynt-t`)
pushed to `/tmp` over TFTP — **no flashing**:

```
[INFO:IMPSystem.cpp]: LIBIMP Version IMP-1.1.0
[INFO:IMPSystem.cpp]: SYSUTILS Version: SYSUTILS-1.1.0
[INFO:IMPSystem.cpp]: CPU Information: T23-N
[INFO:IMPSystem.cpp]: Sensor: cv2003
```
kernel side:
```
probe ok ------->cv2003
cv2003 chip found @ 0x35 (i2c0)
Calibration len = 176288
Ivdc init! direct_mode is 1
cv2003 stream on / cv2003 stream off
```

So third-party IMP userspace initialises against the **vendor's** `tx-isp`,
acquires the sensor and streams it. The SDK version guess was right too: the
vendor build string is `FWIF **ZRT**_release_…` and the matching SDK is
`T23/lib/**1.1.0-zrt**/uclibc/5.4.0` in `gtxaspec/ingenic-lib`.

**Two gotchas that cost time:**
1. prudynt autodetects the sensor from `/proc/jz/sensor/name`. The vendor's
   `tx-isp` **does not create it** (`/proc/jz/` has audio, codecs, debug, helix,
   reset, clock, ddr, gpio, isp, watchdog — no `sensor`). Without it prudynt
   falls back to its built-in `gc2053` and the driver rejects it:
   `Failed to acquire subdev gc2053`. The sensor must be set in the config.
2. **Both** `ubia_t23` and `ubia_first` statically link IMP and hold the ISP;
   both must be stopped, and `touch /tmp/stopWdg` first or the watchdog reboots.

### What still blocks a working stream

**1. prudynt dies with SIGFPE (exit 136) right after `Sensor: cv2003`.** A full
`stream0`/`rtsp` config does *not* fix it, so it is not a zero-valued config
field — on MIPS this is an integer divide-by-zero, most plausibly a frame-rate
or timing value the vendor's `tx-isp` reports differently from thingino's.
Diagnosing further needs a build we can instrument; there is no gdb/strace on
the device.

**2. Only the *static* build can run here.** `prudynt-T23-dynamic` and
`-hybrid` both want `/lib/ld-musl-mipsel.so.1` plus `libmuslshim`,
`libwebsockets`, `libaudioshim`… — i.e. the whole thingino userland. This
rootfs is **uClibc**. So we cannot simply swap in the `1.1.0-zrt` `libimp.so`
we downloaded; the static build bundles whatever libimp gtxaspec linked, and
that may well be the non-ZRT variant — a plausible cause of (1).

**3. Size is the hard structural limit.** `prudynt-T23-static` is **4.5 MB**:
* `/system` (mtd4) is 1728 K total with ~53 K free — it **cannot** be flashed there;
* `/tmp` is tmpfs, and RAM is 37.5 MB with 21 MB reserved for media (`rmem`),
  leaving ~9 MB free. Writing 4.5 MB to tmpfs and then mapping it pushes the box
  into OOM — which is what kept killing `telnetd` mid-transfer, not the network.

⇒ A deployable streamer must be **custom-built**: uClibc, linked against
`1.1.0-zrt`, and trimmed to a size that fits flash or the tiny RAM budget. That
needs a real cross-toolchain (thingino's buildroot on a Linux box); only
binutils is available locally.

### ⚠️ Battery, not software, caused most of the instability
Repeated "mysterious" drops — telnetd vanishing, a TFTP transfer dying at block
2334, `uptime` of 13 s and 22 s appearing unprompted — were the camera
**cold-booting on a failing battery**. A passive watch caught it: 557 s uptime,
then gone, then back with the vendor app running, while we only read. Run this
work on **mains power**; every reboot clears tmpfs and undoes the whole setup.

### The IMP ↔ tx-isp pairing (historical note)
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
