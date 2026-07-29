#!/usr/bin/env bash
# Read the RBX-S73 SPI NOR flash via an RP2040 running pico-serprog.
#
#   ./tools/flash_read.sh [PORT] [SPISPEED] [OUTDIR]
#
# Detects the chip, reads it TWICE, and compares SHA-256: two matching reads are
# the proof that an in-circuit (clip) dump is clean. Read-only — cannot brick.
# Defaults: auto-detect /dev/cu.usbmodem*, spispeed=1M, outdir=captures/
set -uo pipefail

export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
cd "$(dirname "$0")/.."

PORT="${1:-}"
SPEED="${2:-1M}"
OUT="${3:-captures}"

if ! command -v flashrom >/dev/null; then
  echo "flashrom not found (brew install flashrom)" >&2; exit 1
fi

if [ -z "$PORT" ]; then
  PORT=$(ls -1 /dev/cu.usbmodem* 2>/dev/null | head -1)
  if [ -z "$PORT" ]; then
    echo "No /dev/cu.usbmodem* found." >&2
    echo "Is the RP2040 plugged in and running pico-serprog?" >&2
    echo "(If it shows as RPI-RP2 drive, the serprog .uf2 isn't loaded yet.)" >&2
    exit 1
  fi
  echo "auto-detected port: $PORT"
fi

PROG="serprog:dev=${PORT},spispeed=${SPEED}"
mkdir -p "$OUT"
echo "=== programmer: $PROG ==="

echo
echo "--- step 1: detect chip ---"
if ! flashrom -p "$PROG" 2>&1 | tee /tmp/flashrom_detect.txt; then :; fi
if grep -qiE "no eeprom|no flash|could not find|error" /tmp/flashrom_detect.txt \
   && ! grep -qiE "^Found" /tmp/flashrom_detect.txt; then
  cat <<'EOF'

DETECTION FAILED — work through these in order:
  1. Clip orientation: clip pin 1 must be on chip pin 1 (the dimple corner).
  2. Reseat the clip — it must bite all 8 legs squarely.
  3. Verify the 6 mandatory wires: CS(GP5,pin7) MISO(GP4,pin6) MOSI(GP3,pin5)
     CLK(GP2,pin4) 3V3(pin36) GND(pin3).   <-- CS is GP5, NOT GP1
  4. Camera battery MUST be disconnected.
  5. Retry slower:  ./tools/flash_read.sh <PORT> 512K
EOF
  exit 1
fi
echo
grep -iE "^Found|flash chip" /tmp/flashrom_detect.txt || true

echo
echo "--- step 2: read #1 ---"
flashrom -p "$PROG" -r "$OUT/flash_dump1.bin" || { echo "read #1 failed" >&2; exit 1; }
echo "--- step 3: read #2 (verification pass) ---"
flashrom -p "$PROG" -r "$OUT/flash_dump2.bin" || { echo "read #2 failed" >&2; exit 1; }

echo
echo "=== verify ==="
H1=$(shasum -a 256 "$OUT/flash_dump1.bin" | awk '{print $1}')
H2=$(shasum -a 256 "$OUT/flash_dump2.bin" | awk '{print $1}')
SZ=$(wc -c < "$OUT/flash_dump1.bin" | tr -d ' ')
echo "size : $SZ bytes ($((SZ/1024/1024)) MB)"
echo "read1: $H1"
echo "read2: $H2"
if [ "$H1" = "$H2" ]; then
  cp "$OUT/flash_dump1.bin" "$OUT/flash_stock_verified.bin"
  echo
  echo ">>> MATCH — clean dump. Archived as $OUT/flash_stock_verified.bin"
  echo ">>> This is the RESTORE IMAGE. Keep it safe and OUT of git."
  echo ">>> Next: binwalk $OUT/flash_stock_verified.bin"
else
  echo
  echo ">>> MISMATCH — the two reads differ (bus contention or a flaky clip)."
  echo ">>> Try: lower speed (512K), reseat the clip, confirm the battery is out."
  echo ">>> If it never settles, chip-off is the reliable fallback."
  exit 2
fi
