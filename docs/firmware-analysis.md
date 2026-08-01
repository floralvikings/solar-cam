# Firmware Analysis — RBX-S73

Source: **full 8 MB SPI flash dump**, read off-board 2026-08-01 from the *spare*
camera's XMC chip (desoldered with hot air, read via RP2040 + pico-serprog +
SOIC-8 clip). Two independent reads were hash-identical ⇒ clean dump.
Obtained from hardware I own; images are **git-ignored** (`captures/`, `firmware/`).

```
chip   : XMC XM25QH64C/XM25QH64D (8192 kB, SPI NOR)
sha256 : 7eb936ba96c4b5c55df3a98a90598129ffc84e2364fce7d154dd12e9856a2895
file   : captures/flash_stock_verified.bin   (gitignored)
```

> **This dump is the un-brick lifeline for both cameras.** Write it back with the
> same clip (`flashrom … -w`) to restore stock. Keep an off-machine backup.

## Platform
| Item | Value |
|------|-------|
| SoC | **Ingenic T23 (T23ZN)**, MIPS32 XBurst — board `ISVP` |
| Platform/variant | `CAMERA_SOC_T23ZN_cv2003_V1`, `ModelNum=2455` |
| Firmware build | `FWIF ZRT_release_20260316111618` (= OTA version 2455.0.21.10) |
| Bootloader | U-Boot 2013.07 (Mar 03 2025) |
| Kernel | `Linux-3.10.14-Archon`, uImage, **lz4**, load `0x80010000`, entry `0x80389B90` |
| Rootfs | **ramdisk** (`root=/dev/ram0 rw rdinit=/linuxrc`) — hence that partition's high entropy |
| Console | **`console=ttyS0,115200n8`** — the UART console IS enabled, at 115200 |
| Memory | `mem=43M@0x0 rmem=21M@0x2b00000` |
| Wi-Fi/BT | **ESP32 over SDIO** (`esp32_sdio.ko`, `bluetooth.ko`, `btsdio.ko`) |

## Partition map (AUTHORITATIVE — from the `tag` partition)
The U-Boot binary contains a **stale** `mtdparts` string (says 544K tag / 2816K
rootfs). The real layout lives in `tag`, cross-checked against
`BTIF kernel=2240K@0x98000 rootfs=3008K@0x2C8000` and the on-disk magics:

```
jz_sfc:256K(boot),352K(tag),2240K(kernel),3008K(rootfs),1728K(system),
       192K(config),32K(usr),64K(ae),256K(audio),32K(usr_bak),32K(vd),8M@0(all)
```

| # | Name | Offset | Size | Contents (verified) |
|---|------|--------|------|---------------------|
| 0 | boot | `0x000000` | 256K | U-Boot (entropy 5.7) |
| 1 | tag | `0x040000` | 352K | **env/config blocks** (CMDL / ENVI / BTIF / USR0 / FWIF) |
| 2 | kernel | `0x098000` | 2240K | uImage `Linux-3.10.14-Archon` ✓ |
| 3 | rootfs | `0x2C8000` | 3008K | compressed ramdisk (entropy 7.7, no magic) |
| 4 | system | `0x5B8000` | 1728K | **SquashFS v4 / xz** — plain, extracts ✓ |
| 5 | config | `0x768000` | 192K | JFFS2, 98.9% erased (runtime settings) |
| 6 | usr | `0x798000` | 32K | |
| 7 | ae | `0x7A0000` | 64K | auto-exposure data |
| 8 | audio | `0x7B0000` | 256K | SquashFS (prompt sounds) |
| 9 | usr_bak | `0x7F0000` | 32K | |
| 10 | vd | `0x7F8000` | 32K | |

## `system` partition contents (extracted with `unsquashfs`)
- **`ubia_t23`** (5.4 MB) — the vendor's main camera application: P4P stack, cloud
  client, and motor control all live here. Prime target for further RE.
- `bin/`: **`gpiotool`**, `tag_env_info`, `logcat`, `to_t31`
- Modules: `esp32_sdio.ko`, `bluetooth.ko`, `btsdio.ko`, `alarm_led.ko`, `hichannel.ko`
- `mkfs.vfat`

## Device configuration (`tag` → `ENVI` block)
```
[HW]   ae_auto_learn=1; init_vw=2304; init_vh=1296; nrvbs=1; mode=0;
       select_mode=0; is_h264=1; adc_value=10; pkg=184; uart1=1;
       MoveRectNums_x=16; MoveRectNums_y=10; ext_devfunction1=10;
       close_rec=1; close_led=0
[UBIA] main_bitrate=768; sub_bitrate=384; vide_flip=3; ai_vol=57; ao_vol=55;
       md_level=4; battery_cam=1; debug=1; vi_notalk=50; ModelNum=2455;
       ac_freq=1; workmode=0; person_level=2; time_format=0; osd_show=1;
       sec_zoom_start=28
[IR]   ir_mode=auto
```
- **Sensor resolution 2304×1296 (3 MP)** → narrows to the usual T23 3 MP parts
  (SC3335 / SC3338 / GC3003 class). Exact model not yet pinned: the app resolves
  `UBIA_SENSOR_NAME=%s` at runtime, so the name isn't a static string in `system`.
- A second `ENVI` block holds factory defaults (1920×1080, `battery_cam=0`).

## Answering the original key question
**No local RTSP/ONVIF server exists in stock firmware.** Nothing matching
`rtsp|onvif|dropbear|telnetd` in the `system` partition — consistent with
`protocol-notes.md`, where control proved cloud-gated. Local streaming therefore
requires replacing the firmware (thingino/OpenIPC), not enabling a hidden daemon.

## Still to determine (for a thingino/OpenIPC profile)
- [ ] Exact **sensor model** — decompress the lz4 uImage / ramdisk, or let thingino autodetect
- [ ] **GPIO map**: pan/tilt motor, IR-cut, IR LEDs, PIR, battery ADC
      (leads: `bin/gpiotool`, `ubia_t23`; board silk 水平=pan, 垂直=tilt)
- [ ] U-Boot behaviour on a modified image (signature/verify logic)

## Reproducing / restoring
```bash
# read (chip OFF-board, clipped to RP2040 running pico-serprog)
./tools/flash_read.sh /dev/cu.usbmodemXXXX 1M

# restore stock (DANGEROUS — this writes)
flashrom -p serprog:dev=PORT,spispeed=1M -w captures/flash_stock_verified.bin
```
Wiring and the in-circuit-vs-chip-off findings: `hardware-notes.md`.
