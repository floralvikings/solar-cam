"""Stage the SD card for dev work: enable dev mode and put prudynt on it.

Ordering here is deliberate and matters:

1. wait for the vendor app (P4P) — it serves the ioType 46 that fires our hook;
2. fire the hook to get ``telnetd``;
3. create ``rbx_dev`` on the SD card;
4. fire the hook **again** — this is the pass that sees the flag and stops the
   watchdog + vendor apps. It must happen *before* the transfer, because with
   the vendor apps running there is under 1 MB of RAM free and anything large
   gets the OOM killer (which is what kept killing telnetd);
5. only now push prudynt, onto the **SD card** rather than tmpfs, so it costs no
   RAM and survives reboots.

Note the chicken-and-egg in step 4: enabling dev mode kills P4P, so the trigger
has to be sent while it is still alive. After that the only way to fire the hook
again is a reboot.
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, "tools")

import p4p_probe_config as cfg  # noqa: E402
from p4p.lansearch import discover  # noqa: E402
from p4p_relay import open_relay_session  # noqa: E402

TELNET = 2323
SD = "/tmp/mnt/sdcard"


def port_open(host: str, port: int, t: float = 3.0) -> bool:
    s = socket.socket(); s.settimeout(t)
    try:
        return s.connect_ex((host, port)) == 0
    finally:
        s.close()


def p4p_alive(timeout: float = 6.0) -> bool:
    try:
        return bool(discover(cfg.UID, targets=[cfg.BROADCAST, cfg.CAMERA_IP],
                             timeout=timeout))
    except Exception:
        return False


def fire_hook(attempts: int = 10) -> bool:
    """ioType 46 toggles the night light, which persists via tag_env_info."""
    for _ in range(attempts):
        try:
            sess = open_relay_session(verbose=False)
        except RuntimeError:
            time.sleep(10); continue
        if sess.knock_status == "0000":
            for state in (1, 0):
                sess.send_ioctrl(46, bytes([0, 0, 0, 0, 0, 0, state, 0, 0, 0, 0, 0]))
                sess.pump(3.0)
            sess.close()
            return True
        sess.close()
        time.sleep(10)
    return False


def tftp_thread(directory: Path, port: int, stop: threading.Event) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port)); sock.settimeout(1.0)
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
            sock.sendto(struct.pack("!HH", 5, 1) + b"nf\x00", addr); continue
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
        print(f"   [tftp] {name}: {len(data)} bytes @ blksize {blksize}", flush=True)
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
                        print("   [tftp] client error", flush=True); return
            else:
                print(f"   [tftp] timeout at block {block}", flush=True); return
            off += blksize
            if len(chunk) < blksize:
                print(f"   [tftp] complete ({block} blocks)", flush=True); break
            block += 1
        sock.settimeout(1.0)
    sock.close()


class Shell:
    def __init__(self, host: str, timeout: float = 30.0):
        self.s = socket.create_connection((host, TELNET), timeout=10)
        self.s.settimeout(timeout)
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
        return "".join(c for c in out.decode("utf-8", "replace")
                       if c.isprintable() or c in "\r\n").strip()

    def close(self) -> None:
        self.s.close()


def wait_for(pred, label: str, timeout: float = 180.0, step: float = 6.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            print(f"   {label}: ok", flush=True)
            return True
        print(f"   waiting for {label}…", flush=True)
        time.sleep(step)
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary", help="prudynt build to copy onto the card")
    ap.add_argument("--sd", default=SD)
    ap.add_argument("--tftp-port", type=int, default=6969)
    ap.add_argument("--no-dev", action="store_true",
                    help="stage files but do not enable dev mode")
    args = ap.parse_args()

    print("1. waiting for the vendor app (P4P serves our trigger)", flush=True)
    if not wait_for(p4p_alive, "P4P", 240):
        raise SystemExit("camera never came back; power-cycle it")

    print("\n2. firing the hook for telnetd", flush=True)
    if not port_open(cfg.CAMERA_IP, TELNET):
        if not fire_hook():
            raise SystemExit("could not fire the hook")
        if not wait_for(lambda: port_open(cfg.CAMERA_IP, TELNET), "telnetd", 90, 3):
            raise SystemExit("telnetd never came up")
    else:
        print("   telnetd already up", flush=True)

    sh = Shell(cfg.CAMERA_IP)
    print("\n3. SD card state", flush=True)
    print(sh.run(f"mount | grep mmcblk; ls -la {args.sd} 2>&1", 8), flush=True)

    if not args.no_dev:
        print("\n4. enabling dev mode and firing the hook again", flush=True)
        print(sh.run(f"touch {args.sd}/rbx_dev && echo 'rbx_dev created' || "
                     f"echo 'FAILED to write to the card'", 6), flush=True)
        sh.close()
        if not fire_hook():
            raise SystemExit("could not fire the hook a second time")
        time.sleep(12)
        sh = Shell(cfg.CAMERA_IP)
        print(sh.run("ps | grep -c '[u]bia_'; free | grep Mem; "
                     "ls -l /tmp/stopWdg 2>&1", 10), flush=True)

    if args.binary:
        binary = Path(args.binary).resolve()
        staging = binary.parent
        stop = threading.Event()
        threading.Thread(target=tftp_thread, args=(staging, args.tftp_port, stop),
                         daemon=True).start()
        print(f"\n5. copying {binary.name} onto the SD card (not tmpfs)", flush=True)
        size = binary.stat().st_size
        have = sh.run(f"stat -c %s {args.sd}/{binary.name} 2>/dev/null || echo 0", 5)
        if str(size) in have:
            print("   already present, skipping", flush=True)
        else:
            sh.run(f"cd {args.sd} && (tftp -b 1400 -g -r {binary.name} "
                   f"-l {args.sd}/{binary.name} {cfg.CLIENT_IP} {args.tftp_port} "
                   f"> /tmp/tftp.log 2>&1 &)", 3)
            for _ in range(40):
                time.sleep(5)
                got = sh.run(f"stat -c %s {args.sd}/{binary.name} 2>/dev/null || echo 0", 3)
                if str(size) in got:
                    break
        print(sh.run(f"chmod +x {args.sd}/{binary.name}; ls -l {args.sd}/{binary.name}; "
                     f"free | grep Mem", 8), flush=True)
        stop.set()

    sh.close()
    print("\ndone", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
