#!/usr/bin/env python3
"""Capture H.264 video from the RBX-S73 camera over the LAN (cloud-free).

Writes an Annex-B H.264 elementary stream to a file or stdout (pipe into ffmpeg,
go2rtc, MediaMTX, ...). Auto-discovers the view password from the camera's
LanSearchInfo. Only one session per camera at a time (close the UBox live view).

Examples:
    python scripts/capture_h264.py --uid LXKH... --camera-ip 192.168.88.113 \
        --client-ip 192.168.88.20 -o out.h264 --seconds 15
    python scripts/capture_h264.py --uid LXKH... --camera-ip 192.168.88.113 \
        --client-ip 192.168.88.20 -o - | ffmpeg -i - -c copy out.mp4
"""

from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from p4p.client import stream_h264  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Capture cloud-free H.264 from the RBX-S73 over LAN.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--uid", required=True, help="Device UID (20 chars)")
    p.add_argument("--camera-ip", required=True)
    p.add_argument("--client-ip", required=True, help="This host's LAN IP")
    p.add_argument("--broadcast", default="255.255.255.255")
    p.add_argument("-o", "--output", default="-", help="Output file, or - for stdout")
    p.add_argument("--seconds", type=float, help="Stop after N seconds")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    out = sys.stdout.buffer if args.output == "-" else open(args.output, "wb")
    frames = 0
    start = time.time()
    try:
        for frame in stream_h264(
            args.uid, args.camera_ip, args.client_ip, broadcast=args.broadcast
        ):
            out.write(frame)
            out.flush()
            frames += 1
            if frames % 30 == 0:
                print(f"[i] {frames} frames, {time.time()-start:.0f}s", file=sys.stderr)
            if args.seconds and time.time() - start >= args.seconds:
                break
    except KeyboardInterrupt:
        pass
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    finally:
        if out is not sys.stdout.buffer:
            out.close()
    print(f"[done] {frames} H.264 frames in {time.time()-start:.0f}s", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
