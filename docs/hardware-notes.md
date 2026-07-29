# Hardware Notes — RBX-S73

Hardware work became the primary path after local control over P4P proved
**cloud-gated** (see `protocol-notes.md`): the camera acks local ioctrl but never
drives the motor, so root via custom firmware is the only route to real local
PTZ + native RTSP/ONVIF.

**Avoid irreversible changes; back up flash before writing anything.**

## Safety rules
- Determine signal voltage **before** attaching any adapter.
- **Disconnect the battery** before clipping onto the flash.
- Never let a 5 V programmer touch this 3.3 V flash (rules out an unmodified CH341A).
- Back up flash (two matching reads) before any write. Have a recovery plan.

## Board survey (spare/sacrificial camera, teardown 2026-07-28)

| Item | Finding |
|------|---------|
| Main board | silk `S30BT-T23 MAIN VER01 2026xxxx-WiFi` |
| SoC | **Ingenic T23** (`Ingenic T23`, S909…A12-ZN) — *earlier notes assumed T31; T23 is confirmed on this unit* |
| Flash chip | **XMC 25-series SPI NOR, SOIC-8** (`XMC 25QH…`), immediately below/left of the SoC — the dump target |
| Wi-Fi module | `FTJ211LV4` (shielded can) |
| Crystal | 24.000 MHz |
| UART pads | **labeled `GND` / `TXD` / `RXD`**, bottom-left edge by a mounting hole (plated through-holes) |
| Battery/charge board | separate rear PCB, `IP5410 CHARGE`, 18650 cell + JST (V+/V−/NTC) |
| Motor connectors | silk `水平` = pan, `垂直` = tilt; `电池` = battery |
| Sensor | bare CMOS on the reverse side + `IR-CUT` connector |

### UART bring-up — attempted, abandoned
- Adapter: **CP2102** USB-TTL (3.3 V signals), `/dev/cu.usbserial-0001`.
- Result: only **~30–49 sparse garbage bytes per boot** at 115200, even with
  soldered joints and a single reader.
- Measured **~4.5 V between GND and BOTH TXD and RXD** ⇒ the header sits near the
  system/battery rail, **above the CP2102's ~3.6 V input limit** (adapter clamps →
  garbage). Also, the board's power wiring was later found to be **miswired**, so
  the SoC may not have been booting at all during those attempts.
- Two gotchas worth remembering:
  - **Only ONE process may hold the serial port.** Multiple readers steal bytes
    from each other and produce fake "garbage". Verify with
    `lsof /dev/cu.usbserial-0001`.
  - The console is **silent at idle** — it only prints during boot, so every test
    needs a power-cycle.
- If revisited: drop the level (≈1 kΩ series + ≈2 kΩ to GND on camera-TXD →
  adapter-RXD, read-only) or use a level shifter.

## Flash access options (least invasive first)
- [ ] Bootloader commands — blocked (no working console yet)
- [ ] UART shell dump — blocked (see above)
- [x] **SPI flash clip (in-circuit) — CHOSEN PATH** (procedure below)
- [ ] Chip-off (hot-air / low-melt) — fallback only; requires desoldering skill
- [ ] Vendor recovery mode — n/a

---

# SPI flash read via RP2040 + SOIC-8 clip (procedure)

Reads the firmware **without powering the camera board**, sidestepping the UART
level problem entirely. Read-only: **you cannot brick anything by reading.**

## Kit
- **RP2040 board** (Raspberry Pi Pico or any Pico-form clone — the RP2040 chip is
  what matters). Natively **3.3 V**, so no mod and no risk to the flash.
- **SOIC-8 / SOP-8 test clip, 150-mil (narrow)**.
- **Female–female jumper wires** (6 minimum).
- Host tooling (already installed): `flashrom 1.7.0` (with `serprog`), `binwalk 3.1.0`.

## Step 0 — verify the clone board
1. Confirm the main chip is marked **RP2040**.
2. Hold **BOOTSEL** (some clones label it `BOOT`, and add a `RESET`; if so hold
   BOOT and tap RESET), plug USB into the Mac.
3. A USB drive named **`RPI-RP2`** must appear. If it does, the clone is
   Pico-compatible and everything below applies unchanged.
4. If no `RPI-RP2` drive appears, stop — the board isn't RP2040/UF2 compatible.

## Step 1 — load serprog firmware (drag-and-drop, no Windows)
`pico-serprog` turns the RP2040 into a flashrom-compatible SPI programmer.
Prebuilt `.uf2` (staged on the Desktop):
- **primary:** `pico_serprog.uf2` — `opensensor/pico-serprog` v1.0.0
- **backup:** `pico_serprog_libreboot.uf2` — `initdc/libreboot_pico-serprog`
- Both verified: valid UF2 magic + familyID `0xe48bff56` (RP2040).
- Lineage: stacksmashing → kukrimate → libreboot → opensensor. NOTE the upstream
  `stacksmashing/pico-serprog` repo publishes **no releases** (source only).

1. With `RPI-RP2` mounted, **drag `pico_serprog.uf2` onto it**.
2. The drive ejects itself and the board reboots as a serial device — it will
   appear as **`/dev/cu.usbmodem*`**. That's it; firmware is loaded permanently
   (to re-flash later, hold BOOTSEL while plugging in again).

## Step 2 — find pin 1 on the XMC chip
- Pin 1 is marked by a **small dot/dimple** in one corner of the package.
- Numbering runs **counter-clockwise viewed from above**: pins 1→4 down one side,
  5→8 back up the other. So pin 1 and pin 8 are diagonally opposite corners on the
  same end.
- The clip has a **pin-1 indicator** (a mark on the jaw / the red ribbon wire).
  **Pin 1 of the clip must sit on pin 1 of the chip** — backwards = no detection.

## Step 3 — wire it up  (BATTERY DISCONNECTED)

Standard 25-series SPI NOR pinout → the pins **this** firmware uses
(verified in source: `SPI_CS=5, SPI_MISO=4, SPI_MOSI=3, SPI_SCK=2`).
⚠️ **CS is GP5** in the opensensor/kukrimate/libreboot lineage — the older
stacksmashing build used GP1. Wrong CS pin = chip never detected.

| Flash pin | Flash function | RP2040 | Pico physical pin |
|---|---|---|---|
| 1 | **CS#** | **GP5** | **7** |
| 2 | **DO (MISO)** | GP4 | 6 |
| 3 | WP# | 3V3 | 36 |
| 4 | **GND** | GND | 3 |
| 5 | **DI (MOSI)** | GP3 | 5 |
| 6 | **CLK (SCK)** | GP2 | 4 |
| 7 | HOLD#/RESET# | 3V3 | 36 |
| 8 | **VCC** | 3V3 | 36 |

- The **6 bold lines are mandatory**. WP#/HOLD# are usually already pulled high on
  the board; tying them to 3V3 is optional but harmless and can help.
- **Do not** connect VBUS/5 V (pin 40) anywhere.
- Plug the RP2040 into USB **after** the clip is seated, to avoid live-clipping.

## Step 4 — detect the chip
Find the port, then identify the flash (`spispeed` kept low for clip reliability):

```bash
ls /dev/cu.usbmodem*
flashrom -p serprog:dev=/dev/cu.usbmodemXXXX,spispeed=1M
```

Success = flashrom prints the **JEDEC ID + chip name + size** (expect an
`XM25QH…` / `W25Q…`-class part, likely 8 MB / 64 Mbit).

Troubleshooting, in order:
- `No EEPROM/flash device found` → clip orientation (pin 1), reseat the clip, check
  the 6 wires, then retry at `spispeed=512K`.
- Detected but flaky → lower speed further; ensure the battery is disconnected.
- *Multiple chips match* → pass `-c "<CHIPNAME>"` from the printed list.
- **In-circuit caveat:** the clip's 3V3 also feeds the board's rail, which can
  partially wake the T23 and cause SPI bus contention. Mostly benign with the
  battery out; if reads never agree, chip-off is the fallback.

## Step 5 — read twice and verify (the safety net)
Two independent reads that hash-match prove a clean dump:

```bash
./tools/flash_read.sh /dev/cu.usbmodemXXXX        # detect + 2 reads + compare
```
or manually:
```bash
flashrom -p serprog:dev=PORT,spispeed=1M -r captures/flash_dump1.bin
flashrom -p serprog:dev=PORT,spispeed=1M -r captures/flash_dump2.bin
shasum -a 256 captures/flash_dump1.bin captures/flash_dump2.bin   # must match
```
**Matching hashes ⇒ archive it. This file is the restore image / un-brick lifeline
for both cameras.** Keep it out of git (`captures/` and `firmware/` are ignored).

## Step 6 — analyze
```bash
binwalk captures/flash_dump1.bin                 # identify U-Boot / kernel / rootfs
binwalk -eM captures/flash_dump1.bin             # extract (squashfs/jffs2)
strings -n 8 captures/flash_dump1.bin | grep -iE "rtsp|onvif|telnet|dropbear|gpio|motor"
```
Targets: MTD/partition layout, U-Boot env + `bootargs`, sensor model, and the
**GPIO map** (IR-cut, IR LEDs, pan/tilt motor, PIR, battery ADC) — the inputs
needed for a thingino/OpenIPC device profile.

## Step 7 — custom firmware (later, and only after a verified backup)
The T23 is supported by **thingino / OpenIPC** (native RTSP/ONVIF + root).
Sequence that protects the working camera:
1. Verified stock dump archived (Step 5).
2. Flash thingino to the **sacrificial** camera first; tune the device profile
   (video first — pan/tilt, PIR and battery need the GPIO map from Step 6).
3. Only once it works there, flash the **primary** camera.
4. Recovery at every step = write the stock dump back with the same clip
   (`flashrom … -w stock.bin`). Writing is where brick risk lives — reads are safe.
