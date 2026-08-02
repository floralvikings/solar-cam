#!/usr/bin/env python3
"""Standalone H.264 capture, run by go2rtc's exec source.

Writes an Annex-B H.264 elementary stream to stdout (first frame is a keyframe).
go2rtc pipes this into ffmpeg and restreams. Uses the vendored p4p library.

    python3 capture.py --uid <UID> --camera-ip <IP> --client-ip <HA_IP> -o -
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from p4p.client import LanControlSession, stream_h264  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--uid", required=True)
    ap.add_argument("--camera-ip", required=True)
    ap.add_argument("--client-ip", required=True)
    ap.add_argument("--broadcast", default="255.255.255.255")
    ap.add_argument("--control-sock", default=None,
                    help="Unix datagram socket to accept PTZ/ioctrl commands on")
    ap.add_argument("-o", "--output", default="-")
    args = ap.parse_args()
    out = sys.stdout.buffer if args.output == "-" else open(args.output, "wb")
    # With a control socket, use the control-capable session (video + PTZ);
    # without it, the plain video-only generator (unchanged behavior).
    if args.control_sock:
        frames = LanControlSession(
            args.uid, args.camera_ip, args.client_ip,
            broadcast=args.broadcast, control_sock_path=args.control_sock,
        ).frames()
    else:
        frames = stream_h264(
            args.uid, args.camera_ip, args.client_ip, broadcast=args.broadcast
        )
    try:
        for frame in frames:
            out.write(frame)
            out.flush()
    except (BrokenPipeError, KeyboardInterrupt):
        return 0
    except RuntimeError as e:
        print(f"capture error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
