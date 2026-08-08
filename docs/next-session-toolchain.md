# Handoff: building a working streamer (Linux box)

Everything below assumes a **Linux host on the same LAN as the camera**, so it
can both build and drive the device. Splitting build-here/test-there means
copying binaries back and forth for no benefit.

## Where things stand

**Solved and reproducible** (see `firmware-analysis.md`, `thingino-feasibility.md`):

* OTA flashing over the network — `tools/fwflash.py`, done ~6 times, no failures
* Root shell — `telnetd` from the `/system/bin/tag_env_info` hook
* Full 8 MB flash backup of the primary — `captures/primary_mtd11.bin`
* **thingino's libimp works against the vendor `tx-isp`** — every core IMP call
  returns 0, sensor `cv2003` acquired, kernel reports `cv2003 stream on`
* SD-card dev loop — no flashing needed per iteration

**The one blocker:** `prudynt-T23-static` SIGFPEs in the ISP *tuning* pass,
immediately after `IMP_ISP_Tuning_SetTemperStrength`. Ruled out: sensor-only
config, full `stream0`/`rtsp` config, tmpfs vs SD card, vendor apps running vs
stopped. Identical crash every time ⇒ **the fault is in the binary**.

Two candidates:
1. the static build bundles a **non-ZRT** libimp, while this camera is
   `FWIF ZRT_release_*` (matching `T23/lib/1.1.0-zrt` in `gtxaspec/ingenic-lib`);
2. prudynt applies **`SetSensorFPS` last** (confirmed from its own debug strings),
   so earlier tuning ops may divide by a frame rate the stock driver never
   populated — thingino's patched `tx-isp` exposes `/proc/jz/sensor/`, this one
   has no such entry at all.

## Goal

Build prudynt for **T23 / uClibc / SDK 1.1.0-zrt**, statically linked, and
ideally trimmed. Full thingino buildroot is *not* required — `gtxaspec/prudynt-t`
has its own build system and is much lighter.

Size matters: `/system` is a 1728 K partition with ~53 K free, so a 4.5 MB
binary can only run from the SD card. Anything smaller widens the options.

## Setup on the Linux box

```bash
git clone git@github.com:floralvikings/solar-cam.git && cd solar-cam
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt   # if present
sudo apt install squashfs-tools binutils-mipsel-linux-gnu build-essential
```

**Recreate `local/device.json`** — it is gitignored, so it does not come with the
clone, and `client_ip` must be **this Linux box**, not the Mac:

```json
{ "uid": "...", "view_password": "...",
  "camera_ip": "192.168.88.113",
  "client_ip":  "<this-box-lan-ip>",
  "broadcast":  "192.168.88.255" }
```

`client_ip` is baked into `rbxsend` at build time and used as the OTA URL host,
so a stale value means the camera calls home to the wrong machine.

## Build

```bash
git clone https://github.com/gtxaspec/prudynt-t && cd prudynt-t
# SDK libs: https://github.com/gtxaspec/ingenic-lib  ->  T23/lib/1.1.0-zrt/uclibc/5.4.0
# (libimp.so, libalog.so, libsysutils.so — the ZRT variant is the point)
```
Target uClibc, **not musl**: the stock rootfs is uClibc, and the prebuilt
`-dynamic` and `-hybrid` releases both need `/lib/ld-musl-mipsel.so.1` plus the
whole thingino userland, which is why only `-static` was testable here.

## Test loop (no flashing)

The camera already runs the hooked `/system`, so:

```bash
# on the SD card (mounted rw at /tmp/mnt/sdcard)
touch rbx_dev                    # dev mode: stops watchdog + both vendor apps
cp prudynt /tmp/mnt/sdcard/       # or push with tools/sd_setup.py

.venv/bin/python tools/sd_setup.py --binary /path/to/prudynt
```

Order matters and is easy to get wrong:
`wait for P4P -> fire hook (telnetd) -> create rbx_dev -> fire hook again
(dev mode) -> transfer -> run`. Dev mode kills P4P, which serves the ioType 46
that fires the hook, so the trigger must be sent **before** the kill. After
that, only a reboot can fire it again.

## Traps that have already cost hours

* **This busybox is stripped**: no `wget`, `nc`, `head`, `tail`, `wc`, `sed`,
  `awk`, `cut`, `base64`, `gzip`. Use `stat -c %s`, `grep`, `dd`, `tar`/`unzip`.
  Check `captures/recon-0.txt` before assuming a coreutil exists.
* **`/tmp` is tmpfs.** A 4.5 MB binary there costs 4.5 MB of 37.5 MB RAM and
  gets telnetd OOM-killed. Put binaries on the SD card.
* **Flashing needs the vendor app running** — ioType 4631 lives inside
  `ubia_t23`, so dev mode and flashing are mutually exclusive.
* **`touch /tmp/stopWdg` before killing `ubia_t23`**, or `ubia_watchdog` reboots
  the box in ~10 s.
* **Trigger the hook by *changing* a setting.** ioType 46 with the value the
  light already has does not persist, so `tag_env_info` never runs — send both
  states.
* The camera **cold-boots on its own** when the battery is low; run it on mains.
  Every reboot clears tmpfs.

## If the build route stalls

The project goal — RTSP in Home Assistant — is also reachable with **zero device
risk** by bridging the existing local H.264 P4P stream host-side with go2rtc
(`scripts/capture_h264.py` is the starting point). Worth keeping in view if the
libimp rebuild turns into a long haul.
