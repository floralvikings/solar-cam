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
nothing ever clears the flag and every later 4631 is ignored until reboot. After
a *failed* download the spawned thread clears the flag, so probing with a type
that does spawn one is freely repeatable — verified by back-to-back runs.

### `file_type` decides everything (functions named by their `__func__` strings)

The thread at `0x4e6050` re-dispatches on `g_update_type`, and the branches end
in completely different places. **Only `file_type=1` flashes the main SoC.**

| `file_type` | Path | Flashes | Fetch verified live |
|---|---|---|---|
| 0 | — (returns immediately) | nothing; **jams 4631 until reboot** | no fetch |
| **1** | `ubia_http_download` → pthread `download` `0x4188e8` → **`ubia_ota_update_liteos` `0x425364`** | **`/dev/mtd4`** | ✅ 1 request |
| 2 | pthread `download_auto_update` `0x41a98c`, `type=2` | falls to `unknow type=%d` — **nothing** | ✅ 5 requests |
| 7 | MCU image | — | not tested |
| 10 | `download_auto_update`, `type=10` | `/tmp/update_hi3861.bin` (ESP32 Wi-Fi part) | ✅ 5 requests |
| 11 | **rejected at the ioctrl layer** — would have hit `flashcp /dev/mtd3` | nothing | ✅ no fetch, as predicted |

The retry count is a reliable fingerprint: `download_auto_update` has a
`reDownloadCount < 5` loop, so types 2 and 10 produce exactly five connections
one second apart, while type 1 produces a single one. That is how the two
downloaders were told apart on the wire.

`mtd3` is reachable only from `download_auto_update`'s `type == 11` branch, and
`type` is `g_update_type` verbatim (`lw $a1, -0x6170($s0)` at `0x4e61e8`, right
before the call). Since `file_type=11` never spawns a thread, **that branch is
dead on the 4631 path** — confirmed live: type 11 answers 4632 and never fetches.

Both downloaders compose their own request URL as `http://%s/firmware/%s`
(`0x80dc70`), which is why the GET path is `/firmware/` and not the one we
supplied. Only the **host and port** of our `file_url` are honoured; a server
must simply answer whatever path is requested.

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

On success the **header is stripped** and only the payload is flashed. On the
reachable (`file_type=1`) path, `ubia_ota_update_liteos` @`0x425364` does it by
hand rather than via `SaveDownLoadFile`:
```c
system("cp /sbin/flashcp  /tmp");                       // 0x425438
fd = open("/tmp/update.bin", O_WRONLY|O_CREAT);         // 0x425448
s0 = 0x20;                                              // skip the header
while (s0 < total) s0 += write(fd, buf + s0, total - s0);   // 0x42548c
system("/sbin/flashcp -v /tmp/update.bin /dev/mtd4");   // 0x4259c8
```

### Confirmed twice, independently — no vendor image needed
`ubia_ota_update_liteos` (`file_type=1`, flashes mtd4) and `download_auto_update`
(`type=11`, flashes mtd3) each implement the container check **separately**, and
they agree byte-for-byte: same 32-byte header, same word-0 and word-7 zeroing,
same two-pass seeded `crc32_raw`, same `payload = buf + 0x20`. Two independent
implementations agreeing is stronger evidence than a single sample image would
have been, so the "get a real vendor image" blocker below is no longer on the
critical path for validating the *format*.

### Why this matters
* **No signature anywhere.** Integrity is this CRC plus an MD5 that *we supply
  in the same request that names the URL*.
* The reachable path writes **only mtd4 (`system`)** — never mtd0 (U-Boot) or
  mtd2 (kernel), so a bad image cannot stop the board from booting.
* The CRC is a plain checksum over data we author, so a valid image is
  constructible offline: `python scripts/ota_image.py build --payload X --out Y`.

⇒ **Custom firmware over the network, with no hardware modification, is on the
table** — specifically, replacing the `system` SquashFS, which holds `ubia_t23`,
`bin/gpiotool` and the kernel modules. That is the whole vendor application
layer.

> **Recovery caveat — this is not risk-free.** U-Boot and the kernel survive any
> mtd4 content, but `esp32_sdio.ko` (the Wi-Fi driver) lives *in* mtd4. A bad
> image therefore costs the network, and with it any second OTA attempt — the
> only way back is **chip-off + `flashrom -w captures/flash_stock_verified.bin`**.
> "Cannot brick the bootloader" is not the same as "cannot require desoldering".

### Getting a genuine vendor image to validate against — **still blocked**

The container format above is transcribed from the device binary, not confirmed
against a real vendor image. Attempts so far (`tools/ota_check.py`):

| Attempt | Result |
|---|---|
| `POST /api/v2/user/check_version`, real version, no token | `{"code":0,"data":"","msg":"success"}` |
| same, claiming 1.0.21.9 / 1.0.20.0 / 1.0.0.1 (older) | identical empty `data` |
| same with `pkid` corrected from 151 → 1 | identical empty `data` |
| `POST /api/v3/user/qry/device/check_version/v3` | 404 — and `checkVersionV3` has **no callers** in the APK, so it is dead code |

Facts established while trying:
* The v2 endpoint answers **without** `X-Ubia-Auth-UserToken` — the token is not
  what gates it at the transport level.
* The device's real packed version is **`0x0100150a` = `1.0.21.10`**, read live
  from `GET_ADVANCESETTINGS` (961) at body `+0x20` — so `pkid` is **1**. The
  "2455" in `2455.0.21.10` is the *ModelNum* from the `tag` partition, not the
  version's first octet; `pkid_for()` deriving 151 from it was wrong.
* Model string `RBX-S73-WIFI`, product `RBX` (961 body `+0x00` / `+0x10`).
* Lowering the claimed version changes nothing, which suggests the service
  answers from **its own record for the UID** rather than trusting the caller's
  claim — so an account-scoped request is probably required to get it to resolve
  the device at all.

**Next step needs a capture, not more guessing:** run the mitmproxy + WireGuard
setup in `capture-procedure.md`, open the app's firmware-update screen, and save
the real `user/check_version` request. That pins the exact body *and* the token,
after which `tools/ota_check.py --token …` can replay it with a lowered version.

If the vendor turns out to publish no image for this product at all, the only
remaining end-to-end validation is to serve a **CRC-valid image whose payload is
the camera's own current mtd3 content** from `flash_stock_verified.bin` — a
write that restores identical bytes. That is still a real flash write and must
not happen without explicit sign-off and the chip-off restore path ready.

### ✅✅✅ CODE EXECUTION ON THE CAMERA (2026-08-07)

`/system/bin/tag_env_info` is a **working hook**. `ubia_t23` persists settings by
shelling out to it *by bare name*::

    0x4b6194  snprintf(buf, 0x64, "tag_env_info --set UBIA md_level %d", v)
    0x4b61b0  system(buf)

so `/system/bin` must be on `PATH`. Replacing it with a `#!/bin/sh` wrapper that
`exec`s the renamed `tag_env_info.real` therefore runs our code on every setting
change, with zero functional breakage.

**Proof (network-free).** Flipped the image in the UBox app, power-cycled, and
the flip **persisted**. The live flip is just the video pipeline in RAM;
*persistence* only happens via `tag_env_info`, and after the swap ours is the
only `tag_env_info` on `PATH`. Nothing else could have written it.

**Why nothing ever reached the listener:** this vendor busybox ships no usable
network client. The payload tried `wget --post-file`, `wget` GET, `nc`, `telnet`
and `ping` across three flashed images and not one produced a TCP connection —
while the hook itself was firing the whole time. *Absence of a callback proved
nothing about execution; do not use exfil as a liveness signal on this device.*

Hooks that do **not** work, and why:
* `/system/mkfs.vfat` — the format thread reaches `beqz $s3, 0x4dc808` with `s3`
  unconditionally zero (set at 0x4dc494, never rewritten on any path in), so it
  always runs the **bare** `mkfs.vfat`, never the absolute `/system/` form at
  0x4dc824. And `/system` — unlike `/system/bin` — is not on `PATH`.
* ioType 804 SETMOTIONDETECT — unhandled on this firmware: no response, and 961
  comes back byte-identical.

**Consequence:** we control the whole partition, so we are not limited to
whatever applets busybox happens to have. A statically-linked MIPS binary shipped
*inside* `/system` and launched from the wrapper sidesteps the missing-`wget`
problem entirely — and makes an on-camera RTSP server a packaging job rather than
a research problem.

### Live system inventory (2026-08-07, via the hook + `rbxsend`)

23 KB of `/tmp/rbx_recon.txt` retrieved off the running camera. Raw copy:
`captures/recon-0.txt` (gitignored). The load-bearing facts:

| Fact | Value |
|---|---|
| Privilege | **`uid=0(root)`** — everything below runs as root |
| Kernel | `Linux Zeratul 3.10.14-Archon #1 PREEMPT Fri Jul 11 15:58:39 CST 2025 mips` |
| `PATH` | **`/system/bin:/bin:/sbin:/usr/bin:/usr/sbin`** — our hook dir is *first* |
| Sensor | `export SENSOR=cv2003` (confirmed, no longer inferred) |
| `/config` | `/dev/mtdblock5` **jffs2 rw** — persistent writable storage |
| `/system` | `/dev/mtdblock4` squashfs **ro** |
| **`/dev/mtd11`** | **`"all"`, 0x800000 — the entire 8 MB flash as one device** |
| busybox | 498212 bytes at `/bin/busybox` |

**Why every exfil attempt failed:** the applet list has **no `wget` and no `nc`**.
Three flashed images tried them. What *does* exist: **`telnetd`**, `tftp`,
`ping`, `nslookup`, `udhcpc`, `vi`, `dd`, `flashcp`, `flash_eraseall`.

`/etc/init.d/rcS` ends:
```sh
export PATH=/system/bin:/bin:/sbin:/usr/bin:/usr/sbin
export SENSOR=cv2003            # also SOC_TYPE=SOC_T23ZN, FLASH_TYPE=NOR
mount -t squashfs /dev/mtdblock4 /system
insmod /system/hichannel.ko
#telnetd                        # <-- vendor commented it out
/system/ubia_t23   &
```
So `ubia_t23` is launched from `rcS` by absolute path (a wrapper there would
work), and **telnetd is present but deliberately disabled**.

`ps` caught the hook mid-flight, which is independent confirmation:
```
216 root  /bin/sh -c tag_env_info --set UBIA vide_flip 2
217 root  {tag_env_info} /bin/sh /system/bin/tag_env_info --se
```

**Two consequences worth acting on:**
1. `telnetd` already exists — an interactive root shell is one line, no new
   binary needed.
2. `/dev/mtd11` exposes the **whole 8 MB flash**. The *primary* camera's unique
   per-device data (UID/MAC/Wi-Fi/AE calibration) can now be backed up **over
   the network** (`dd if=/dev/mtd11 | rbxsend`) instead of by chip-off — and
   writing kernel/rootfs becomes reachable too, which the 4631 OTA path alone
   could not do.

### 🔓 Root shell + full flash backup, over the network (2026-08-07)

`busybox telnetd` ships on the device and `rcS` merely comments it out, so the
hook re-enables what the vendor already built:

```sh
pgrep telnetd >/dev/null 2>&1 || telnetd -l /bin/sh -p 2323
```

Fires on the next setting change; then `telnet <camera> 2323` is an interactive
**root** shell (`uid=0(root)`, host `Zeratul`). Note it starts from the *hook*,
not at boot, so a power-cycle needs another setting change to bring it back.

**The primary camera's whole 8 MB flash was then pulled off over TCP** — the
operation that previously required chip-off:

```sh
dd if=/dev/mtd11 bs=64k | /system/bin/rbxsend     # on the camera
.venv/bin/python tools/recv_blob.py --out captures/primary_mtd11.bin
# 8388608 bytes @ ~1.6 MB/s, sha256 4e89f3e6…
```

Per-partition comparison against the spare's chip-off dump:

| Partition | Identical across units? |
|---|---|
| `boot`, `kernel`, `rootfs`, `audio` | **yes** — same firmware build |
| `tag` | no (245 B) — per-device config/UID |
| `config` | no (663 B) — runtime settings |
| `usr`, `usr_bak` | no (2241 B each) |
| `ae` | no (8733 B) — **auto-exposure calibration** |
| `vd` | no (20 B) |

⇒ the differing partitions are exactly the per-device identity, and they are now
backed up.

**This also closed an open question.** `mtd4` in the dump is **byte-identical
(sha256 match) to the image we flashed**, which *directly observes* the `flashcp`
write. The earlier no-op rehearsal could only ever mark it "strongly indicated",
because writing identical bytes leaves nothing to see.

> ⚠️ `primary_mtd11.bin` is **not** a pristine stock image — its `system`
> partition is our hooked build. To restore the primary to stock, either flash
> `captures/noop_mtd4.img` over OTA, or splice the spare's stock `system` slice
> (`0x5B8000..0x768000`) into this dump before writing it back.

### Complete recipe for a network flash (nothing here is guesswork any more)

1. Open a relay session (`tools/p4p_relay.py`) — LAN only, no cloud.
2. Send ioType **4631** with:
   * `file_type = 1` — the only value that reaches a main-SoC flash
   * `version` = anything ≠ the installed `0x0100150a`, else the handler
     early-outs; `0x7fffffff` is safe
   * `file_url` = `http://<us>:<port>/anything` — only host:port are honoured
   * `file_size` = the image length
   * `md5sum` = **ignored** — `ubia_FirmwareUpdateProc` copies only
     `payload[0x2c..0xac]` (the URL) and `payload[8]` (file_size) into the
     thread's parameter block; the MD5 at `payload[12..44]` is never read.
     Integrity on this path is the CRC32 alone.
3. Answer *any* path the camera GETs with `32-byte header || payload`, built by
   `scripts/ota_image.py build`. Serve a `Content-Length` (`not find
   Content-Length:` @`0x80e362` is a hard failure).
4. The camera CRCs it, strips the header, writes the payload to
   `/tmp/update.bin`, and runs `flashcp -v /tmp/update.bin /dev/mtd4`.

### ✅ Executed end-to-end (2026-08-07) — the camera flashed and survived

A **no-op rehearsal** was run against the primary camera: payload = the `system`
partition sliced straight out of `flash_stock_verified.bin`, wrapped by
`scripts/ota_image.py build`, served by `tools/fwflash.py`.

```
-> 4631 FIRMWARE_UPDATE_REQ  file_type=1  file_size=1769504
   >>> GET http://<us>/firmware/ HTTP/1.1 -> 200, sending 1769504 bytes
   >>> body sent in full
   <- 4632 0000000000000000          (command ack)
   <- 4630 0000000049000000          (progress 73)
   <- 4630 0000000064000000          (progress 100)
```

The camera then rebooted and came back **completely healthy**: LAN-search
answers, `ubia_t23` is running, the relay session + knock + ioctrl all work, and
961 returns byte-identical device data. So the container format, the CRC rule,
the `file_type=1` routing and the whole download path are **confirmed on real
hardware**, not just in the disassembly.

*Scope of that claim:* progress reaching 100 plus a clean reboot makes the
`flashcp` write **strongly indicated**, but by design a no-op write leaves
nothing observable — mtd4 could not be read back without a shell. Writing
*modified* content is what would demonstrate the write directly.

### ✅✅ CUSTOM-BUILT FIRMWARE BOOTS (2026-08-07)

Second flash, this time a **`mksquashfs`-produced image of our own** rather than
the vendor's bytes: stock `/system` with `mkfs.vfat` swapped for a script and the
original kept as `mkfs.vfat.real` (`tools/build_system_image.py`). 1716256 bytes,
progress `0x37` → `0x64`, reboot — and the camera came back with a **byte-identical
961 response**.

That is the whole claim, closed:
* our SquashFS **mounted** — so `mksquashfs -comp xz -b 131072` output is
  accepted by this kernel's decompressor;
* `esp32_sdio.ko` loaded **from the partition we wrote** — Wi-Fi came up, which
  is the only reason the camera could answer at all;
* `ubia_t23` is running out of our image, with full ioctrl.

⇒ **Custom firmware, built on a workstation, installed over the network, with no
hardware access.** The chip-off path is now a recovery mechanism, not a
prerequisite.

Note the mid-transfer progress value differed between the two flashes (`0x49`
for the 1769504-byte image, `0x37` for the 1716256-byte one), confirming 4630
tracks the real transfer rather than replaying a fixed sequence.

**Progress is reported back on ioType 4630**, which the app's headers call
`FIRMWARE_UPDATE_CHECK_RSP` — an 8-byte body whose **second u32 LE is a
percentage**. Observed during a real transfer: `00000000 49000000` (0x49 = 73),
then repeated `00000000 64000000` (0x64 = 100). The immediate `4632` is only the
command acknowledgement; 4630 is what tracks the actual write.

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
