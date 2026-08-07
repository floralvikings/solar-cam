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

---

# Live UART boot log (primary camera, 2026-08-02)

3-pin header soldered to the labeled GND/TXD/RXD through-holes; CP2102 at
**115200 8N1** (GND, camera TXD→adapter RX, camera RXD→adapter TX, **no VCC**).
Result: clean log, 99% printable. `tools/uart_console.py` (capture/break/cmd).

## Key findings
- **No U-Boot console.** The SPL is an Ingenic **fast-boot** loader
  (`spl_time:202ms`, `kernel_len:4722604 rootfs_len:7542272`) that jumps straight
  to the kernel. No banner, no `Hit any key`, and `break` mode (keystrokes spammed
  from before power-on) never caught a prompt. U-Boot exists in flash but is not
  executed on this path.
- **No shell on the console.** Enter yields no prompt; output-only.
  ⇒ Neither U-Boot (`loady`/`sf write`) nor userspace flashing is available.
  **Flashing/backup must be done at the chip** (clip/programmer).
- **Wi-Fi module is a HiSilicon `hi3861`**, NOT the ESP32 (`get_wifi3861_status`,
  `ubia_sta_connect_wifi … send ssid key to hi3861`). The `esp32_sdio.ko` present
  in the `system` partition is an unused driver.
- Watchdog: `t31_wdt`, timeout 30 s (T23/T31 share drivers).
- App version `Ver:1.0.21.10`; SPL banner `Ver:241028-T23ZN-SINGLE-…`.
- Runtime config matches the `tag` ENVI block exactly (2304×1296, bitrates,
  battery_cam, ModelNum 2455 …).
- Camera reboots itself periodically (battery/power-management driven).

## Sensor fingerprint (name NOT stored in plaintext anywhere)
The SPL reads a 256-byte **`SENS`** descriptor — two copies in the `tag`
partition at **0x41000** and **0x48000**. All fields verified against the SPL's
own printout:

| Field | Value |
|---|---|
| magic | `SENS` (`0x534e4553`) |
| crc | `0x8a2e3135` |
| mclk | `0x016e3600` = 24 MHz |
| pin_mask | `0x000343ff` |
| **i2c_addr** | **0x35** |
| i2c_index | 0 |
| reg_addr_size / value_size | 2 / 1 |
| init regs (16-bit addr) | `0x3029=00, 0x302a=00, 0x3401=01, 0x3440=03, 0x3442=00, 0x3806=01, 0x3158=01` |

The descriptor is **name-less** — the model name lives only in the compressed
kernel driver. Resolution 2304×1296 + T23 points at the usual 3 MP SmartSens-class
part, but this is **not confirmed**. Resolve it later by letting thingino probe,
or by reading the sensor chip ID over I²C once a root shell exists.

## Kernel decompression — partial
The uImage payload is a **vendor-modified lz4**. Header decoded and validated:
`u32 block_size=0x10000`, `u32 total=4722604` (exactly matching the boot log's
`kernel_len`). The payload itself does not parse as standard lz4 block or frame
format (tried raw/framed at several offsets, and a per-block length-prefix
scheme). Not pursued further — not required for the thingino path.

## OTA / network flash path — **the camera fetches from a URL we choose**

**Confirmed 2026-08-07, live, twice.** `tools/fwtest.py` sent ioType **4631**
(`IOTYPE_USER_IPCAM_FIRMWARE_UPDATE_REQ`) over a relay-path session
(`tools/p4p_relay.py`, 0x1105 — see `protocol-notes.md`) with `file_type=1` and
a URL pointing at this host. The camera answered **4632** and then connected to
our listener:

```
!!! TCP connect from <camera>:45864 -> answering 404
    GET http://<us>/firmware/ HTTP/1.1
    Accept:text/html,application/xhtml+xml,...
    User-Agent:Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537...
    Host:<us>
    Connection:close
```

No cloud involvement. The probe is safe by construction: the listener always
returns `404` and the offered MD5 is deliberately wrong, so the download cannot
complete and `flashcp` is never reached.

### Handler: `ubia_FirmwareUpdateProc` @ `0x4e6940`
```c
if (g_update_flag)                       // @0x939e94 — else-path, no 4632 reply
    ...;
if (version == current_version_for_type) // early out; replies 4632, does nothing
    ...;
reply 4632 {progress=0, result=0};  g_update_flag = 1;
switch (file_type) {                     // payload[4], saved to g_update_type @0x939e90
  case 1: case 2: pthread_create(0x4e6050);   // <-- the ONLY downloading branch
  case 7: case 10:  MCU / 4G-modem images
  default:          return;                   // <-- file_type 0 does NOTHING
}
```
**`file_type=0` is a trap:** it latches `g_update_flag` and spawns no thread, so
nothing ever clears the flag and every later 4631 is ignored until reboot. Use 1
or 2. After a *failed* download the thread clears the flag (`0x4e63f0`), so
probing is freely repeatable — verified by two back-to-back runs.

### Call chain (each function identified by its own `__func__` string)
```
ubia_FirmwareUpdateProc  0x4e6940   ioType 4631 handler
  └ pthread  0x4e6050               waits ≤15 s for a busy flag (gp+0xadd)
      └ ubia_http_download 0x41ea40
          └ pthread  download_auto_update 0x41a98c   <-- HTTP, CRC, flash
```
`download_auto_update` takes one heap argument, `struct { int type; char url[]; }`,
and composes its own request URL as `http://%s/firmware/%s` (`0x80dc70`) — which
is why the GET path is `/firmware/` and not the path we supplied. Only the
**host and port** of our `file_url` are honoured; a server must simply answer
whatever path is requested. The captured request matched this function's format
strings exactly (`GET %s HTTP/1.1`, that Accept/User-Agent/Host/Connection set),
which is how we know our probe lands here and not on some other download path.

## OTA container format — **fully recovered**

Implemented and unit-tested in `scripts/ota_image.py` (`verify` / `build`).
32-byte header, then the payload:

| Offset | Size | In CRC? | Meaning |
|--------|------|---------|---------|
| `0x00` | u32 | **no** — zeroed before hashing | purpose unidentified |
| `0x04`–`0x18` | 6 × u32 | yes | purpose unidentified; **nothing on this path validates them** |
| `0x1c` | u32 | zeroed before hashing | **CRC-32 of the image; must be non-zero** |

Verification, transcribed from `0x41c248`:
```c
copy = header;  copy.word[0] = 0;  copy.word[7] = 0;   // 0x41c29c / 0x41c2a0
crc  = crc32_raw(0,   &copy,        32);               // 0x41c2a4
crc  = crc32_raw(crc, buf + 0x20,   total - 32);       // 0x41c2bc
valid = (stored != 0) && (crc == stored);              // 0x41c968 / 0x41c2c8
```

`crc32_raw` @`0x4c1b14` is a **table-less reflected CRC-32** (poly `0xEDB88320`)
with **no initial inversion and no final inversion** — the seed goes in as-is and
the accumulator comes back as-is, which is what makes the two chained calls above
equivalent to one pass over `header' || payload`. In Python:
`zlib.crc32(data, seed ^ 0xffffffff) ^ 0xffffffff`. The unit tests assert this
against an instruction-for-instruction transcription of the loop.

On success the **header is stripped** and only the payload is flashed:
```c
SaveDownLoadFile("/tmp/update.bin", buf + 0x20, total - 0x20);   // 0x41d140
system("/sbin/flashcp -v /tmp/update.bin /dev/mtd3");            // 0x41d304
```

### Why this matters
* **No signature anywhere.** Integrity is this CRC plus an MD5 that *we supply
  in the same request that names the URL*.
* It writes **only mtd3 (rootfs) and mtd4 (system)** — never mtd0 (U-Boot) or
  mtd2 (kernel), so a bad image cannot brick the bootloader.
* The CRC is a plain checksum over data we author, so a valid image is
  constructible offline: `python scripts/ota_image.py build --payload X --out Y`.

⇒ **Custom firmware over the network, with no hardware modification, is on the
table.**

**Not yet known / unverified:**
* The semantics of header words 1–6. They are covered by the CRC but unread on
  this path, so all-zero should work — *untested against a real device.*
* Whether `Content-Length` is mandatory (`not find Content-Length:` @`0x80e362`
  suggests it is) and whether a chunked reply is tolerated.
* A **second, richer container** exists for the curl/cloud path
  (`pCurlOtaHead->stUpdateHead`): a multi-record archive logging
  `imageTotalLen %d sensorType %d Read %d records:` and per record
  `index %d Name = %s, offset = %d, len = %d crc %x`. It uses the *same* CRC
  routine. Not needed for the 4631 path, but it is probably the shape of the
  vendor's published images — worth confirming against a real one before
  trusting the simple format end-to-end.

## Consequence for installing custom firmware
No secure boot (U-Boot only does a uImage CRC32), so custom firmware **will**
boot. Two write paths now exist:
1. **Network OTA (above)** — no disassembly, no soldering, bootloader-safe.
   Preferred, pending the image-header format.
2. **chip-off → clip → flashrom → resolder** — still the only way to back up the
   *primary* camera's unique per-device data (UID/MAC/Wi-Fi/AE calibration), and
   the recovery path if an OTA image leaves the device unbootable.
