"""RBX-S73 OTA container: parse, verify and build — entirely offline.

The camera can be told to fetch a firmware image over plain HTTP from any host
(ioType 4631, see docs/firmware-analysis.md). What it does with the bytes is
implemented in ``download_auto_update`` (``ubia_t23`` @0x41a98c). This module is
a transcription of that function's validation, so a candidate image can be
checked on a workstation before anything is ever served to a device.

Layout — **32-byte header, then the payload**::

    +0x00  u32   NOT covered by the CRC (zeroed before hashing)
    +0x04  u32 |
    +0x08  u32 |
    +0x0c  u32 |  covered by the CRC; purpose not yet identified, and
    +0x10  u32 |  nothing on this path validates their values
    +0x14  u32 |
    +0x18  u32 |
    +0x1c  u32   CRC-32 of the image; must be non-zero

Verification, exactly as the device does it (@0x41c248)::

    copy = header with word[0] and word[7] (the CRC) zeroed
    crc  = crc32_raw(copy, seed=0)                 # 32 bytes
    crc  = crc32_raw(payload, seed=crc)            # content_length - 32 bytes
    valid = (stored_crc != 0) and (crc == stored_crc)

``crc32_raw`` is the routine at 0x4c1b14: a table-less **reflected CRC-32**
(poly 0xEDB88320) with **no initial inversion and no final inversion** — the
seed is used as-is and the accumulator is returned as-is. That is what makes the
two-call chaining above equivalent to one pass over ``header || payload``.

This layout is confirmed by **two independent implementations** in the firmware
that agree byte-for-byte — ``ubia_ota_update_liteos`` @0x425364 (reached with
``file_type=1``, flashes ``/dev/mtd4``) and ``download_auto_update`` @0x41a98c
(``type=11``, flashes ``/dev/mtd3``, unreachable via ioType 4631).

There is **no signature**: integrity is this CRC plus an MD5 that the client
supplies in the very same request that names the URL. On success the device
writes only the payload — the header is stripped::

    fd = open("/tmp/update.bin", O_WRONLY|O_CREAT)
    s0 = 0x20;  while (s0 < total) s0 += write(fd, buf + s0, total - s0)
    system("/sbin/flashcp -v /tmp/update.bin /dev/mtd4")

Usage::

    python scripts/ota_image.py verify image.bin
    python scripts/ota_image.py build --payload rootfs.bin --out image.bin
"""

from __future__ import annotations

import argparse
import struct
import sys
import zlib
from dataclasses import dataclass

HEADER_LEN = 32
CRC_OFFSET = 0x1C
HEADER_WORDS = HEADER_LEN // 4
POLY = 0xEDB88320
MASK = 0xFFFFFFFF


class OtaImageError(ValueError):
    """The bytes are not a well-formed OTA container."""


# --- the CRC routine @0x4c1b14 ----------------------------------------------

def crc32_raw(data: bytes, seed: int = 0) -> int:
    """Reflected CRC-32 with neither pre- nor post-inversion.

    ``zlib.crc32`` applies both, so they are undone on the way in and out. The
    equivalence with the firmware's loop is asserted in the unit tests against
    :func:`crc32_raw_bitwise`.
    """
    return zlib.crc32(data, (seed & MASK) ^ MASK) ^ MASK


def crc32_raw_bitwise(data: bytes, seed: int = 0) -> int:
    """Instruction-for-instruction transcription of 0x4c1b14 (slow; the oracle).

    ``v0 = seed; for each byte { v0 ^= byte; 8x { v0 = (v0 >> 1) ^ (poly if v0 & 1 else 0) } }``
    """
    crc = seed & MASK
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (POLY if crc & 1 else 0)
    return crc & MASK


# --- header ------------------------------------------------------------------

@dataclass(frozen=True)
class OtaHeader:
    """The 32-byte header as eight little-endian u32s."""

    words: tuple[int, ...]

    @property
    def crc(self) -> int:
        """The stored CRC (word 7)."""
        return self.words[7]

    def to_bytes(self) -> bytes:
        return struct.pack("<8I", *self.words)


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    reason: str
    stored_crc: int
    computed_crc: int
    payload_len: int

    def __str__(self) -> str:
        verdict = "VALID" if self.ok else f"INVALID — {self.reason}"
        return (f"{verdict}\n"
                f"  stored crc   : 0x{self.stored_crc:08x}\n"
                f"  computed crc : 0x{self.computed_crc:08x}\n"
                f"  payload      : {self.payload_len} bytes "
                f"(written to /dev/mtd4 via file_type=1)")


def parse(image: bytes) -> OtaHeader:
    """Parse the header. Raises :class:`OtaImageError` if the image is too short."""
    if len(image) < HEADER_LEN:
        raise OtaImageError(f"image is {len(image)} bytes, header alone is {HEADER_LEN}")
    if len(image) == HEADER_LEN:
        raise OtaImageError("image is a bare header with no payload")
    return OtaHeader(struct.unpack_from("<8I", image, 0))


def header_crc_input(header: bytes) -> bytes:
    """The header as hashed: word 0 and the CRC word zeroed (@0x41c29c/0x41c2a0)."""
    masked = bytearray(header[:HEADER_LEN])
    struct.pack_into("<I", masked, 0, 0)
    struct.pack_into("<I", masked, CRC_OFFSET, 0)
    return bytes(masked)


def payload_of(image: bytes) -> bytes:
    """The bytes the device would write to /tmp/update.bin and flash."""
    return image[HEADER_LEN:]


def compute_crc(image: bytes) -> int:
    """CRC the device will compute for ``image`` (header pass, then payload)."""
    crc = crc32_raw(header_crc_input(image[:HEADER_LEN]))
    return crc32_raw(payload_of(image), seed=crc)


def verify(image: bytes) -> VerifyResult:
    """Decide the image exactly as ``download_auto_update`` does."""
    try:
        header = parse(image)
    except OtaImageError as exc:
        return VerifyResult(False, str(exc), 0, 0, 0)
    computed = compute_crc(image)
    payload_len = len(image) - HEADER_LEN
    if header.crc == 0:
        return VerifyResult(False, "stored CRC is zero, which the device rejects "
                                   "outright (beqz $s7 @0x41c968)",
                            header.crc, computed, payload_len)
    if header.crc != computed:
        return VerifyResult(False, "CRC mismatch", header.crc, computed, payload_len)
    return VerifyResult(True, "", header.crc, computed, payload_len)


def build(payload: bytes, *, words: tuple[int, ...] = (0,) * 7) -> bytes:
    """Wrap ``payload`` in a header whose CRC the device would accept.

    ``words`` supplies header words 0..6; word 7 is computed. Their meaning is
    still unknown and this path ignores them, so the default of all-zero is a
    deliberate "nothing asserted" rather than a known-good value.
    """
    if len(words) != HEADER_WORDS - 1:
        raise ValueError(f"expected {HEADER_WORDS - 1} header words, got {len(words)}")
    if not payload:
        raise ValueError("payload is empty")
    image = bytearray(struct.pack("<7I", *words) + b"\x00\x00\x00\x00" + payload)
    struct.pack_into("<I", image, CRC_OFFSET, compute_crc(bytes(image)))
    return bytes(image)


# --- CLI ---------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("verify", help="check an image the way the camera would")
    v.add_argument("image")

    b = sub.add_parser("build", help="wrap a payload in a valid header")
    b.add_argument("--payload", required=True, help="raw partition image to flash")
    b.add_argument("--out", required=True)
    b.add_argument("--word", type=lambda s: int(s, 0), action="append", default=None,
                   metavar="N", help="header word 0..6 (repeat up to 7x; default 0)")

    args = ap.parse_args(argv)

    try:
        if args.cmd == "verify":
            with open(args.image, "rb") as fh:
                image = fh.read()
            result = verify(image)
            header = OtaHeader(struct.unpack_from("<8I", image.ljust(HEADER_LEN, b"\0"), 0))
            print(f"{args.image}: {len(image)} bytes")
            print("  header words :", " ".join(f"{w:08x}" for w in header.words))
            print(result)
            return 0 if result.ok else 1

        with open(args.payload, "rb") as fh:
            payload = fh.read()
        words = tuple((args.word or [])[:7]) + (0,) * (7 - len(args.word or []))
        image = build(payload, words=words)
        with open(args.out, "wb") as fh:
            fh.write(image)
        print(f"wrote {args.out}: {len(image)} bytes "
              f"({HEADER_LEN} header + {len(payload)} payload)")
        print(verify(image))
        return 0
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
