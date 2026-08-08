"""Build a modified /system OTA image with an SD-card-controlled dev hook.

Hook: /system/bin/tag_env_info
------------------------------
``ubia_t23`` persists settings by shelling out to ``tag_env_info``::

    0x4b6194  snprintf(buf, 0x64, "tag_env_info --set UBIA md_level %d", v)
    0x4b61b0  system(buf)

That is a **bare name** resolved through ``PATH``
(``/system/bin:/bin:/sbin:/usr/bin:/usr/sbin``), and the binary ships in
``/system/bin`` — so replacing it with a wrapper that ``exec``s the renamed real
binary runs our code on every setting change while breaking nothing.

Trigger it deliberately with **ioType 46** (night light), sending *both* states:
the firmware only persists a value that actually changes.

What the wrapper does
---------------------
1. starts ``telnetd`` if not already running (busybox ships it; ``rcS`` merely
   comments it out);
2. **optional dev mode**, enabled by a file on the SD card, once per boot: stop
   the watchdog, then the two vendor apps, freeing the ISP;
3. **optional init script** from the SD card, once per boot.

Points 2 and 3 are deliberately *opt-in via the SD card* rather than
unconditional. Killing ``ubia_t23`` outright would destroy P4P — which serves
the ioType 46 that fires this hook — so the hook would be removing its own
trigger. The hook also fires on the vendor's own motion-driven light changes,
which would kill the apps at random. With the flag on the card, normal operation
is the default, one file toggles dev mode, and **pulling the card reverts
everything**.

``rbx_init.sh`` also means the camera's startup behaviour can be changed by
editing a file on the card — no reflashing per iteration.

Ordering matters: ``/tmp/stopWdg`` must exist *before* the kill, or
``ubia_watchdog`` reboots the box in ~10 s.

Usage::

    .venv/bin/python tools/build_system_image.py --host <your-lan-ip>
    .venv/bin/python tools/fwflash.py captures/system_hook.img --confirm

Then, on the SD card:
    touch rbx_dev              # enable dev mode (stops the vendor apps)
    cp rbx_init.sh .           # optional, runs once per boot
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
SDCARD = "/tmp/mnt/sdcard"          # where ubia_t23 mounts /dev/mmcblk0p1

WRAPPER = r"""#!/bin/sh
# Stands in for /system/bin/tag_env_info (stock kept as tag_env_info.real).
# Runs on every setting change; execs the real binary so settings still persist.

# 1. interactive shell, idempotent
pgrep telnetd >/dev/null 2>&1 || telnetd -l /bin/sh -p __TELNET__

SD=__SDCARD__

# 2. dev mode -- opt in by creating rbx_dev on the SD card. NOT unconditional:
#    killing ubia_t23 also kills P4P, which serves the ioType 46 that fires this
#    hook. stopWdg must come first or the watchdog reboots us in ~10s.
if [ -f "$SD/rbx_dev" ] && [ ! -f /tmp/.rbx_dev_done ]; then
  : > /tmp/.rbx_dev_done
  touch /tmp/stopWdg
  killall ubia_t23 ubia_first
fi

# 3. startup hook from the SD card, once per boot -- lets us change what the
#    camera runs without reflashing.
if [ -x "$SD/rbx_init.sh" ] && [ ! -f /tmp/.rbx_init_done ]; then
  : > /tmp/.rbx_init_done
  "$SD/rbx_init.sh" > "$SD/rbx_init.log" 2>&1 &
fi

exec __REAL__ "$@"
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
    ap.add_argument("--host", required=True,
                    help="this host's LAN IP, baked into rbxsend")
    ap.add_argument("--http-port", type=int, default=8080)
    ap.add_argument("--telnet-port", type=int, default=2323)
    ap.add_argument("--sdcard", default=SDCARD)
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

    wrapper = (WRAPPER
               .replace("__TELNET__", str(args.telnet_port))
               .replace("__SDCARD__", args.sdcard)
               .replace("__REAL__", "/system/bin/tag_env_info.real"))
    assert "__" not in wrapper, "unfilled placeholder"

    work = Path(tempfile.mkdtemp(prefix="rbx-system-"))
    try:
        sqfs = work / "stock.sqfs"
        sqfs.write_bytes(stock)
        tree = work / "tree"
        run(["unsquashfs", "-d", str(tree), "-f", str(sqfs)])
        before = tree_hashes(tree)
        print(f"unpacked {len(before)} files from mtd4 (stock)")

        target = tree / "bin" / "tag_env_info"
        if not target.exists():
            raise SystemExit("bin/tag_env_info missing from the stock image")
        target.rename(tree / "bin" / "tag_env_info.real")
        target.write_text(wrapper)
        target.chmod(0o755)
        print("hooked bin/tag_env_info (execs tag_env_info.real; settings still work)")
        print(f"   telnetd on :{args.telnet_port}")
        print(f"   dev mode   : create {args.sdcard}/rbx_dev")
        print(f"   init hook  : {args.sdcard}/rbx_init.sh")

        sender = tree / "bin" / "rbxsend"
        mips_sender.build(args.host, args.http_port, sender, work)
        sender.chmod(0o755)
        print(f"added bin/rbxsend ({sender.stat().st_size} bytes) -> "
              f"{args.host}:{args.http_port}")

        # Earlier images also shadowed mkfs.vfat in /system/bin. That hook never
        # fired (ioType 896 never reaches the absolute path) and it masked the
        # real mkfs.vfat on PATH, which would break SD-card formatting.
        stray = tree / "bin" / "mkfs.vfat"
        if stray.exists():
            stray.unlink()
        print("bin/mkfs.vfat not installed (it shadowed the real one)")

        after = tree_hashes(tree)
        changed = {k for k in set(before) | set(after) if before.get(k) != after.get(k)}
        expected = {"bin/tag_env_info", "bin/tag_env_info.real", "bin/rbxsend"}
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
    finally:
        if args.keep:
            print(f"work dir kept: {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
