"""One-shot dev loop: push prudynt to the camera and run it, without flashing.

Everything lives in tmpfs, so a reboot undoes the lot — which makes this safe to
iterate on. The sequence is:

  1. serve the binary over TFTP (busybox has ``tftp``; ``rbxsend`` is one-way)
  2. trigger the /system/bin/tag_env_info hook via ioType 46 to start telnetd
  3. ``touch /tmp/stopWdg``  — the vendor's own watchdog stop-file, without which
     killing ubia_t23 reboots the box in ~10 s
  4. kill ubia_t23 **and ubia_first** (both statically link IMP and hold the ISP)
  5. pull prudynt into /tmp, write /etc/prudynt.cfg, run it
  6. report its log, the kernel's view, and any listening port

Why the sensor must be configured explicitly: prudynt reads
``/proc/jz/sensor/name`` to autodetect, and the **vendor's tx-isp does not create
that entry** (thingino's patched driver does). Without it prudynt falls back to
its compiled-in default ``gc2053`` and the driver rejects it with
``Failed to acquire subdev gc2053``. This camera is ``cv2003`` at i2c 0x35,
2304x1296 (from the kernel cmdline's init_vw/init_vh).

Usage::

    .venv/bin/python tools/prudynt_try.py --binary <path-to-prudynt>
    .venv/bin/python tools/prudynt_try.py --binary … --fps 20 --sensor cv2003
"""

from __future__ import annotations

import argparse
import shutil
import socket
import struct
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, "tools")

import p4p_probe_config as cfg  # noqa: E402
from p4p_relay import open_relay_session  # noqa: E402

TELNET_PORT = 2323
NIGHTLIGHT = 46


# --- tiny read-only TFTP server (same protocol as tools/tftp_serve.py) -------
def tftp_thread(directory: Path, port: int, stop: threading.Event) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.settimeout(1.0)
    while not stop.is_set():
        try:
            req, addr = sock.recvfrom(2048)
        except socket.timeout:
            continue
        if len(req) < 4 or struct.unpack("!H", req[:2])[0] != 1:
            continue
        fields = req[2:].split(b"\x00")
        name = Path(fields[0].decode("utf-8", "replace")).name
        opts = {fields[i].decode().lower(): fields[i + 1].decode()
                for i in range(2, len(fields) - 1, 2) if fields[i]}
        target = directory / name
        if not target.is_file():
            sock.sendto(struct.pack("!HH", 5, 1) + b"not found\x00", addr)
            continue
        blksize = 512
        if "blksize" in opts:
            blksize = max(8, min(int(opts["blksize"]), 8192))
            sock.settimeout(5.0)
            sock.sendto(struct.pack("!H", 6) + b"blksize\x00"
                        + str(blksize).encode() + b"\x00", addr)
            try:
                sock.recvfrom(1024)
            except socket.timeout:
                blksize = 512
        data = target.read_bytes()
        print(f"   [tftp] serving {name}: {len(data)} bytes, blksize {blksize}")
        sock.settimeout(5.0)
        block, off = 1, 0
        while True:
            chunk = data[off:off + blksize]
            pkt = struct.pack("!HH", 3, block & 0xFFFF) + chunk
            for _ in range(6):
                sock.sendto(pkt, addr)
                try:
                    resp, raddr = sock.recvfrom(1024)
                except socket.timeout:
                    continue
                if raddr == addr and len(resp) >= 4:
                    op, ack = struct.unpack("!HH", resp[:4])
                    if op == 4 and ack == (block & 0xFFFF):
                        break
                    if op == 5:
                        print("   [tftp] client error"); return
            else:
                print(f"   [tftp] timeout at block {block}"); return
            off += blksize
            if len(chunk) < blksize:
                print(f"   [tftp] complete ({block} blocks)")
                break
            block += 1
        sock.settimeout(1.0)
    sock.close()


# --- camera helpers ----------------------------------------------------------
def telnet_open(host: str, timeout: float = 2.0) -> bool:
    s = socket.socket(); s.settimeout(timeout)
    try:
        return s.connect_ex((host, TELNET_PORT)) == 0
    finally:
        s.close()


def fire_hook(attempts: int = 8) -> bool:
    """ioType 46 (night light) runs through tag_env_info, which is our hook.

    Both values are sent, because the firmware only persists a setting that
    actually *changes* — sending the value the light already has does not reach
    tag_env_info, so the hook never fires.
    """
    for _ in range(attempts):
        try:
            sess = open_relay_session(verbose=False)
        except RuntimeError:
            time.sleep(12); continue
        if sess.knock_status == "0000":
            for state in (1, 0):
                sess.send_ioctrl(NIGHTLIGHT,
                                 bytes([0, 0, 0, 0, 0, 0, state, 0, 0, 0, 0, 0]))
                sess.pump(3.0)
            sess.close()
            return True
        sess.close()
        print(f"   knock={sess.knock_status}, retrying…")
        time.sleep(12)
    return False


class Shell:
    def __init__(self, host: str):
        self.s = socket.create_connection((host, TELNET_PORT), timeout=10)
        self.s.settimeout(12)
        time.sleep(1)
        try:
            self.s.recv(4096)
        except socket.timeout:
            pass

    def run(self, cmd: str, wait: float = 5.0) -> str:
        self.s.sendall(cmd.encode() + b"\n")
        time.sleep(wait)
        out = b""
        try:
            while True:
                c = self.s.recv(65536)
                if not c:
                    break
                out += c
        except socket.timeout:
            pass
        text = out.decode("utf-8", "replace")
        return "".join(c for c in text if c.isprintable() or c in "\r\n").strip()

    def close(self) -> None:
        self.s.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary", required=True, help="prudynt build to push")
    ap.add_argument("--sensor", default="cv2003")
    ap.add_argument("--i2c", default="0x35")
    ap.add_argument("--fps", type=int, default=15)
    ap.add_argument("--width", type=int, default=2304)
    ap.add_argument("--height", type=int, default=1296)
    ap.add_argument("--loglevel", default="INFO", help="prudynt general.loglevel")
    ap.add_argument("--bitrate", type=int, default=2000)
    ap.add_argument("--rtsp-port", type=int, default=554)
    ap.add_argument("--tftp-port", type=int, default=6969)
    ap.add_argument("--settle", type=float, default=25.0,
                    help="seconds to let prudynt run before reading its log")
    args = ap.parse_args()

    binary = Path(args.binary).resolve()
    if not binary.is_file():
        raise SystemExit(f"{binary} not found")

    staging = Path(tempfile.mkdtemp(prefix="prudynt-"))
    shutil.copy(binary, staging / "prudynt")
    stop = threading.Event()
    threading.Thread(target=tftp_thread, args=(staging, args.tftp_port, stop),
                     daemon=True).start()
    print(f"tftp serving {binary.name} ({binary.stat().st_size} bytes) "
          f"on :{args.tftp_port}")

    try:
        if not telnet_open(cfg.CAMERA_IP):
            print("starting telnetd via the hook (ioType 46)…")
            if not fire_hook():
                raise SystemExit("could not trigger the hook")
            for _ in range(60):
                if telnet_open(cfg.CAMERA_IP):
                    break
                time.sleep(1)
            else:
                raise SystemExit("telnetd never came up")
        print("shell is up")
        sh = Shell(cfg.CAMERA_IP)

        print("\n--- freeing the ISP (watchdog stop-file, then both vendor apps) ---")
        print(sh.run("touch /tmp/stopWdg; killall ubia_t23 ubia_first; sleep 5; "
                     "ps | grep -c '[u]bia_'; free | grep Mem", 12))

        # Skip the 4.5 MB transfer if it is already there from a previous run --
        # tmpfs survives until reboot, and holding a telnet session open across
        # the whole transfer is the least reliable part of this loop.
        size = binary.stat().st_size
        have = sh.run("stat -c %s /tmp/prudynt 2>/dev/null || echo 0", 4)
        if str(size) in have:
            print(f"\n--- prudynt already present ({size} bytes), skipping transfer ---")
        else:
            print("\n--- pulling prudynt (detached, then polled) ---")
            sh.run(f"rm -f /tmp/prudynt; cd /tmp && (tftp -b 1400 -g -r prudynt "
                   f"-l /tmp/prudynt {cfg.CLIENT_IP} {args.tftp_port} "
                   f"> /tmp/tftp.log 2>&1 &)", 3)
            for _ in range(30):
                time.sleep(5)
                got = sh.run("stat -c %s /tmp/prudynt 2>/dev/null || echo 0", 3)
                if str(size) in got:
                    break
            print(sh.run("chmod +x /tmp/prudynt; ls -l /tmp/prudynt", 5))

        # A sensor-only config gets through IMP init but then dies with SIGFPE:
        # prudynt divides by stream fields (fps/gop) that default to zero. The
        # stream0 and rtsp sections below are what stop that.
        print("\n--- writing /etc/prudynt.cfg ---")
        lines = [
            "general: {",
            f'  loglevel = "{args.loglevel}";',
            "};",
            "sensor: {",
            f'  model = "{args.sensor}";',
            f"  i2c_address = {args.i2c};",
            f"  fps = {args.fps};",
            f"  width = {args.width};",
            f"  height = {args.height};",
            "};",
            "stream0: {",
            "  enabled = true;",
            '  format = "H264";',
            f"  width = {args.width};",
            f"  height = {args.height};",
            f"  fps = {args.fps};",
            f"  gop = {args.fps * 2};",
            f"  max_gop = {args.fps * 4};",
            f"  bitrate = {args.bitrate};",
            "  buffers = 2;",
            '  mode = "CBR";',
            "  profile = 2;",
            "  rotation = 0;",
            "  audio_enabled = false;",
            '  rtsp_endpoint = "ch0";',
            "};",
            "stream1: {",
            "  enabled = false;",
            "};",
            "stream2: {",
            "  enabled = false;",
            "};",
            "rtsp: {",
            f"  port = {args.rtsp_port};",
            '  name = "rbx-s73";',
            f"  est_bitrate = {args.bitrate};",
            "  auth_required = false;",
            "};",
        ]
        # Sent over TFTP as one operation. Writing it line-by-line over telnet
        # meant ~30 round trips and the session kept resetting mid-config.
        (staging / "prudynt.cfg").write_text("\n".join(lines) + "\n")
        print(sh.run(f"mkdir -p /etc/config; rm -f /etc/prudynt.cfg; "
                     f"tftp -g -r prudynt.cfg -l /etc/prudynt.cfg "
                     f"{cfg.CLIENT_IP} {args.tftp_port}; "
                     f"cp /etc/prudynt.cfg /etc/config/prudynt.cfg; "
                     f"cat /etc/prudynt.cfg", 15))

        print("\n--- running prudynt ---")
        print(sh.run("dmesg -c >/dev/null; cd /tmp && ./prudynt 2>&1; echo \"[exit=$?]\"",
                     args.settle + 15))
        print("\n--- kernel ---")
        print(sh.run("dmesg | grep -viE 'Stack :|Call Trace|^\\[<|^ +[0-9a-f]{8} '", 10))
        print("\n--- listening ports ---")
        print(sh.run("netstat -ln 2>/dev/null | grep '^tcp'; pidof prudynt || echo 'prudynt not running'", 8))
        sh.close()
    finally:
        stop.set()
        shutil.rmtree(staging, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
