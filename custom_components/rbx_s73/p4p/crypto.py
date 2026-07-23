"""UBIA/TUTK P4P packet obfuscation codec (canonical copy for the daemon).

Reverse-engineered from ``libUBICAPIs.so`` (``p4p_crypto_encode``). This is a
duplicate of ``scripts/pcaptools/ubia_crypto.py`` kept here so the ``p4p``
package is self-contained and independently packageable; ``tests/
test_crypto_parity.py`` asserts the two never diverge.

It is not encryption: a hardcoded 32-byte XOR key plus a fixed byte permutation
and per-word bit rotations. Provides no real confidentiality.

Per 16-byte block ``encode`` applies, in order:
    1. rotate each 4-byte LE word RIGHT by (offset+1): 1,5,9,13
    2. XOR with KEY
    3. p4p_Swap fixed permutation
    4. rotate each 4-byte LE word RIGHT by (offset+3): 3,7,11,15
A trailing partial block (<16 bytes) is XOR+Swap only. ``decode`` inverts it.
"""

from __future__ import annotations

import struct

# Hardcoded key at .rodata 0xb7b1 in libUBICAPIs.so (32 bytes; blocks use the
# first 16). Ships in every install -> not a device secret.
KEY = b"I believe 1 ^ill win the battle!"

# encoded[i] = plain[_SWAP[n][i]] -- read from the p4p_Swap disassembly.
_SWAP: dict[int, tuple[int, ...]] = {
    2: (1, 0),
    4: (2, 3, 0, 1),
    8: (7, 4, 3, 2, 1, 6, 5, 0),
    16: (11, 9, 8, 15, 13, 10, 12, 14, 2, 1, 5, 0, 6, 4, 7, 3),
}

_MASK = 0xFFFFFFFF


def _rotl(v: int, n: int) -> int:
    n &= 31
    return v & _MASK if n == 0 else ((v << n) | (v >> (32 - n))) & _MASK


def _rotr(v: int, n: int) -> int:
    n &= 31
    return v & _MASK if n == 0 else ((v >> n) | (v << (32 - n))) & _MASK


def _swap(block: bytes) -> bytes:
    t = _SWAP.get(len(block))
    return block if t is None else bytes(block[t[i]] for i in range(len(block)))


def _unswap(block: bytes) -> bytes:
    t = _SWAP.get(len(block))
    if t is None:
        return block
    out = bytearray(len(block))
    for i, src in enumerate(t):
        out[src] = block[i]
    return bytes(out)


def _xor(block: bytes) -> bytes:
    return bytes(b ^ KEY[i] for i, b in enumerate(block))


def _rot_words(block: bytes, base: int, right: bool) -> bytes:
    out = bytearray(len(block))
    for j in range(0, len(block) - 3, 4):
        (v,) = struct.unpack_from("<I", block, j)
        n = j + base
        struct.pack_into("<I", out, j, _rotr(v, n) if right else _rotl(v, n))
    tail = len(block) - (len(block) // 4) * 4
    if tail:
        out[len(block) - tail :] = block[len(block) - tail :]
    return bytes(out)


def encode(data: bytes) -> bytes:
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
        out += _swap(_xor(data[off:]))
    return bytes(out)


def decode(data: bytes) -> bytes:
    out = bytearray()
    off = 0
    while len(data) - off >= 16:
        blk = data[off : off + 16]
        blk = _rot_words(blk, 3, right=False)
        blk = _unswap(blk)
        blk = _xor(blk)
        blk = _rot_words(blk, 1, right=False)
        out += blk
        off += 16
    if off < len(data):
        out += _xor(_unswap(data[off:]))
    return bytes(out)
