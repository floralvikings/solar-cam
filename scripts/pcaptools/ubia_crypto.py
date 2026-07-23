"""UBIA/TUTK P4P packet obfuscation codec.

Reverse-engineered from ``libUBICAPIs.so`` (see docs/protocol-notes.md and
docs/apk-analysis.md). The SDK calls this "crypto" but it is a fixed,
keyless-in-practice obfuscation: a hardcoded 32-byte XOR key plus a fixed
byte permutation and per-word bit rotations. It provides **no real
confidentiality** -- any LAN host that speaks it can read/produce packets.

Per 16-byte block, ``p4p_crypto_encode`` applies:

    1. p4p_DWORDbitshift(dir=right) each 4-byte LE word by (j+1)      # j=block offset
    2. p4p_XOR with KEY
    3. p4p_Swap  (fixed 16-byte permutation)
    4. p4p_DWORDbitshift(dir=right) each word by (j+3)

A trailing partial block (< 16 bytes) is only XOR+Swap'd (no rotations),
matching the tail path in the binary. ``decode`` inverts the whole thing.

Offsets/opcodes referenced elsewhere live in AVIOCTRLDEFs (docs/apk-analysis).
This module handles only the transport obfuscation, never credentials.
"""

from __future__ import annotations

import struct

# Hardcoded key at .rodata 0xb7b1 in libUBICAPIs.so (32 bytes; blocks use the
# first 16). Not a secret in any meaningful sense -- it ships in every copy of
# the app -- so it is fine to keep here. Device UIDs/passwords are NOT.
KEY = b"I believe 1 ^ill win the battle!"

# p4p_Swap output tables: encoded[i] = plain[SWAP[n][i]]. Read directly from
# the disassembly of p4p_Swap for each supported length.
_SWAP: dict[int, tuple[int, ...]] = {
    2: (1, 0),
    4: (2, 3, 0, 1),
    8: (7, 4, 3, 2, 1, 6, 5, 0),
    16: (11, 9, 8, 15, 13, 10, 12, 14, 2, 1, 5, 0, 6, 4, 7, 3),
}

_MASK = 0xFFFFFFFF


def _rotl(v: int, n: int) -> int:
    n &= 31
    if n == 0:
        return v & _MASK
    return ((v << n) | (v >> (32 - n))) & _MASK


def _rotr(v: int, n: int) -> int:
    n &= 31
    if n == 0:
        return v & _MASK
    return ((v >> n) | (v << (32 - n))) & _MASK


def _swap(block: bytes) -> bytes:
    table = _SWAP.get(len(block))
    if table is None:
        return block
    return bytes(block[table[i]] for i in range(len(block)))


def _unswap(block: bytes) -> bytes:
    table = _SWAP.get(len(block))
    if table is None:
        return block
    out = bytearray(len(block))
    for i, src in enumerate(table):
        out[src] = block[i]
    return bytes(out)


def _xor(block: bytes) -> bytes:
    return bytes(b ^ KEY[i] for i, b in enumerate(block))


def _rot_words(block: bytes, base: int, right: bool) -> bytes:
    """Rotate each 4-byte LE word. The rotation amount is (byte_offset + base),
    matching p4p_crypto_encode's loop where the shift passed to
    p4p_DWORDbitshift is (loop_index + base) and loop_index steps 0,4,8,12.
    So the four words rotate by base, base+4, base+8, base+12."""
    out = bytearray(len(block))
    for j in range(0, len(block) - 3, 4):
        (v,) = struct.unpack_from("<I", block, j)
        n = j + base
        r = _rotr(v, n) if right else _rotl(v, n)
        struct.pack_into("<I", out, j, r)
    tail = len(block) - (len(block) // 4) * 4
    if tail:
        out[len(block) - tail :] = block[len(block) - tail :]
    return bytes(out)


def encode(data: bytes) -> bytes:
    """Obfuscate a P4P payload exactly as ``p4p_crypto_encode`` does."""
    out = bytearray()
    off = 0
    while len(data) - off >= 16:
        blk = data[off : off + 16]
        blk = _rot_words(blk, 1, right=True)
        blk = _xor(blk)
        blk = _swap(blk)
        blk = _rot_words(blk, 3, right=True)
        out += blk
        off += 16
    if off < len(data):
        tail = data[off:]
        out += _swap(_xor(tail))
    return bytes(out)


def decode(data: bytes) -> bytes:
    """Invert :func:`encode` (i.e. ``p4p_crypto_decode``)."""
    out = bytearray()
    off = 0
    while len(data) - off >= 16:
        blk = data[off : off + 16]
        blk = _rot_words(blk, 3, right=False)  # undo ROTR(3) -> ROTL(3)
        blk = _unswap(blk)
        blk = _xor(blk)
        blk = _rot_words(blk, 1, right=False)  # undo ROTR(1) -> ROTL(1)
        out += blk
        off += 16
    if off < len(data):
        tail = data[off:]
        out += _xor(_unswap(tail))
    return bytes(out)
