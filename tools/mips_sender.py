"""Build ``rbxsend``: a tiny static MIPS binary that pipes stdin to a TCP socket.

The camera's busybox ships **no** network client — ``wget``, ``nc``, ``telnet``
and ``ping`` were all tried across three flashed images and none produced a
single TCP connection, while the shell hook was demonstrably running. Since we
own the whole ``/system`` partition we are not stuck with the vendor's applets:
we can just ship our own.

Written in raw MIPS assembly against Linux syscalls rather than compiled against
a libc, because (a) no MIPS cross-*compiler* is available here, only binutils,
and (b) it keeps the result under 1 KB, which matters when the partition has
~53 KB of headroom.

Target: MIPS32r2, little-endian, o32 ABI, statically linked, no interpreter.

o32 syscall convention: number in ``$v0``, arguments in ``$a0``-``$a3``,
``syscall``, result in ``$v0`` with the error flag in ``$a3``. The socket-call
block in the o32 table is alphabetically ordered (accept 4165 … socket 4180),
which is the cross-check for the two numbers that matter here.

Usage on the device (``/system/bin`` is on PATH, which is what makes the hook
work at all)::

    some_command | rbxsend
    rbxsend < /tmp/rbx_recon.txt
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

AS = "mipsel-linux-gnu-as"
LD = "mipsel-linux-gnu-ld"
STRIP = "mipsel-linux-gnu-strip"

SOURCE = r"""
    .set    noreorder
    .text
    .globl  _start
    .ent    _start

    .equ    SYS_exit,    4001
    .equ    SYS_read,    4003
    .equ    SYS_write,   4004
    .equ    SYS_close,   4006

/*
 * The o32 socket block is contiguous and alphabetical, so `connect` always sits
 * 13 below `socket`. Rather than betting the whole flash cycle on my recollection
 * that the pair is (4180, 4167), scan a small window and accept only the
 * candidate whose socket() AND connect() both succeed. A wrong number returns
 * ENOSYS with $a3 set, and a right-numbered-but-wrong-call returns EBADF or
 * ENOTSOCK, so a candidate that passes both is the real pair.
 */
_start:
    li      $s2, 4172               /* first candidate for SYS_socket */

try_candidate:
    li      $a0, 2                  /* AF_INET     */
    li      $a1, 2                  /* SOCK_STREAM */
    li      $a2, 0
    move    $v0, $s2
    syscall
    nop
    bnez    $a3, next_candidate
    nop
    move    $s0, $v0                /* candidate fd */

    move    $a0, $s0
    la      $a1, sockaddr
    li      $a2, 16
    addiu   $v0, $s2, -13           /* SYS_connect = SYS_socket - 13 */
    syscall
    nop
    beqz    $a3, copy_loop          /* both worked -> this is the pair */
    nop

    move    $a0, $s0                /* close the bogus fd and move on */
    li      $v0, SYS_close
    syscall
    nop

next_candidate:
    addiu   $s2, $s2, 1
    li      $t0, 4190
    bne     $s2, $t0, try_candidate
    nop
    b       bail
    nop

copy_loop:
    li      $a0, 0
    la      $a1, buf
    li      $a2, 4096
    li      $v0, SYS_read
    syscall
    nop
    bnez    $a3, bail
    nop
    blez    $v0, bail               /* EOF */
    nop
    move    $s1, $v0

    move    $a0, $s0
    la      $a1, buf
    move    $a2, $s1
    li      $v0, SYS_write
    syscall
    nop
    bnez    $a3, bail
    nop
    b       copy_loop
    nop

bail:
    li      $a0, 0
    li      $v0, SYS_exit
    syscall
    nop
    .end    _start

    .data
    .align  2
sockaddr:
    .byte   2, 0                        /* sin_family = AF_INET, u16 LE   */
    .byte   __PORT_HI__, __PORT_LO__    /* sin_port, network order        */
    .byte   __IP0__, __IP1__, __IP2__, __IP3__
    .byte   0, 0, 0, 0, 0, 0, 0, 0

    .bss
    .align  2
buf:
    .space  4096
"""


def toolchain_missing() -> list[str]:
    return [t for t in (AS, LD, STRIP) if not shutil.which(t)]


def render(host: str, port: int) -> str:
    octets = [int(x) for x in host.split(".")]
    if len(octets) != 4 or not all(0 <= o <= 255 for o in octets):
        raise ValueError(f"bad IPv4 address: {host}")
    if not 0 < port < 65536:
        raise ValueError(f"bad port: {port}")
    src = (SOURCE
           .replace("__PORT_HI__", str((port >> 8) & 0xFF))
           .replace("__PORT_LO__", str(port & 0xFF)))
    for i, octet in enumerate(octets):
        src = src.replace(f"__IP{i}__", str(octet))
    return src


def build(host: str, port: int, out: Path, workdir: Path) -> Path:
    """Assemble, link and strip rbxsend for ``host:port``. Returns ``out``."""
    missing = toolchain_missing()
    if missing:
        raise SystemExit("missing toolchain: " + ", ".join(missing)
                         + "\n  brew install mipsel-linux-gnu-binutils")
    asm = workdir / "rbxsend.S"
    obj = workdir / "rbxsend.o"
    asm.write_text(render(host, port))
    for cmd in (
        [AS, "-EL", "-march=mips32r2", "-mabi=32", "-o", str(obj), str(asm)],
        [LD, "-EL", "-e", "_start", "-o", str(out), str(obj)],
        [STRIP, str(out)],
    ):
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise SystemExit(f"{cmd[0]} failed:\n{proc.stdout}\n{proc.stderr}")
    return out


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--out", default="captures/rbxsend")
    args = ap.parse_args()
    with tempfile.TemporaryDirectory() as td:
        path = build(args.host, args.port, Path(args.out), Path(td))
    print(f"wrote {path}: {path.stat().st_size} bytes -> {args.host}:{args.port}")
