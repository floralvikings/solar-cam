#!/usr/bin/env python3
"""Decode camera<->cloud P4P traffic to find inbound COMMAND packets.

Goal: locate the packet the cloud sends the camera when you press PTZ in the app.
That is the packet we would need to forge to control (and firmware-update) the
camera without any hardware access.

Usage:
    tools/cloud_cmd_decode.py CAPTURE.pcap --camera-ip 192.168.x.x [--quiet-types]

Reads the pcap via tshark, de-obfuscates each payload with p4p.crypto, and prints
a timeline of P4P message types by direction. Keepalive/video chatter is folded
away so anything unusual (i.e. a command) stands out. Diff an idle capture against
a PTZ capture: the type that appears ONLY in the PTZ one is the command.
"""
from __future__ import annotations
import argparse, os, subprocess, sys, struct, collections

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from p4p.crypto import decode as p4p_decode  # noqa: E402
from p4p.packet import MAGIC                 # noqa: E402

# high-volume/uninteresting types (media + keepalive), from protocol-notes.md
NOISE = {0x140A, 0x1409, 0x1406, 0x1405}
NAMES = {
    0x1001: "cloud lookup req", 0x1002: "cloud lookup rsp",
    0x1101: "session connect req", 0x1102: "session connect rsp",
    0x1105: "peer-addr exch req", 0x1106: "peer-addr exch rsp",
    0x1301: "LAN search req", 0x1302: "LAN search rsp",
    0x1307: "lanstreamreq", 0x1308: "lanstreamrsp",
    0x1309: "stream start", 0x130A: "stream accept",
    0x130B: "knock", 0x130C: "knock rsp", 0x130D: "knock confirm",
    0x1401: "IOCTRL (command!)", 0x1402: "ioctrl ack",
    0x1405: "alive", 0x1406: "keepalive", 0x1409: "kcp ack", 0x140A: "media",
}


def tshark_rows(pcap: str):
    cmd = ["tshark", "-r", pcap, "-Y", "udp && udp.payload", "-T", "fields",
           "-e", "frame.time_relative", "-e", "ip.src", "-e", "ip.dst",
           "-e", "udp.srcport", "-e", "udp.dstport", "-e", "udp.payload"]
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit(f"tshark failed: {out.stderr[:300]}\n"
                         "(export PATH=/opt/homebrew/bin:$PATH)")
    for line in out.stdout.splitlines():
        f = line.split("\t")
        if len(f) >= 6 and f[5]:
            yield f


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("--camera-ip", required=True)
    ap.add_argument("--show-noise", action="store_true",
                    help="also list media/keepalive packets")
    args = ap.parse_args()

    cam = args.camera_ip
    counts: dict[tuple[str, int], int] = collections.Counter()
    interesting = []
    peers: dict[str, int] = collections.Counter()

    for t, src, dst, sport, dport, payhex in tshark_rows(args.pcap):
        raw = bytes.fromhex(payhex.replace(":", ""))
        dec = None
        for cand in (raw,):
            try:
                d = p4p_decode(cand)
                if d[:4] == MAGIC:
                    dec = d
            except Exception:
                pass
        if dec is None:
            if raw[:4] == MAGIC:
                dec = raw
            else:
                continue
        if len(dec) < 10:
            continue
        mt = struct.unpack_from("<H", dec, 8)[0]
        inbound = (dst == cam)
        direction = "cloud->CAM" if inbound else "CAM->cloud"
        remote = src if inbound else dst
        counts[(direction, mt)] += 1
        peers[remote] += 1
        if mt not in NOISE or args.show_noise:
            body = dec[16:16 + min(48, len(dec) - 16)]
            interesting.append((float(t), direction, remote, mt, body.hex()))

    print(f"=== {args.pcap} (camera {cam}) ===")
    print("\n--- message types by direction ---")
    for (d, mt), n in sorted(counts.items(), key=lambda kv: -kv[1]):
        flag = "   <<< COMMAND CANDIDATE" if (d == "cloud->CAM" and mt not in NOISE) else ""
        print(f"  {d}  0x{mt:04x} {NAMES.get(mt,'?'):24} x{n}{flag}")

    print("\n--- remote peers ---")
    for p, n in peers.most_common(10):
        print(f"  {p:16} x{n}")

    print(f"\n--- non-media packets timeline ({len(interesting)}) ---")
    for t, d, remote, mt, body in interesting[:80]:
        print(f"  {t:8.2f}s {d} {remote:16} 0x{mt:04x} {NAMES.get(mt,'?'):22} {body[:64]}")
    if len(interesting) > 80:
        print(f"  … {len(interesting)-80} more")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
