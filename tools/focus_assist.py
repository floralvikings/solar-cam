#!/usr/bin/env python3
"""Live focus assist: repeatedly grab a frame and print a sharpness score.

Rotate the M12 lens barrel slowly; the score PEAKS at best focus. Higher = sharper.
Judging a laggy MJPEG stream by eye is unreliable — this gives you a number.

    ./tools/focus_assist.py [seconds_per_sample] [total_seconds]

Requires the camera to be FREE (disable the HA integration). Read-only: video only,
no PTZ, no writes. Config from env / local/device.json.
"""
import os, subprocess, shutil, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p4p_probe_config as cfg  # noqa: E402  (also puts repo root on sys.path)
from p4p.client import stream_h264, _has_sps  # noqa: E402
from PIL import Image, ImageFilter  # noqa: E402

OUT = "/Users/cbrinkman/.claude/jobs/0eb50487/tmp"
FF = shutil.which("ffmpeg") or "/usr/local/bin/ffmpeg"
PER = float(sys.argv[1]) if len(sys.argv) > 1 else 6.0
TOTAL = float(sys.argv[2]) if len(sys.argv) > 2 else 180.0


def sharpness(path: str) -> float:
    """Variance of a Laplacian — the standard focus metric. Higher = sharper."""
    im = Image.open(path).convert("L")
    w, h = im.size
    im = im.crop((w // 6, h // 6, w * 5 // 6, h * 5 // 6))  # ignore edges/OSD
    lap = im.filter(ImageFilter.Kernel((3, 3), [0, 1, 0, 1, -4, 1, 0, 1, 0], scale=1))
    hist = lap.histogram()
    n = sum(hist)
    if not n:
        return 0.0
    mean = sum(i * c for i, c in enumerate(hist)) / n
    return sum(c * (i - mean) ** 2 for i, c in enumerate(hist)) / n


def grab(tag: str) -> str | None:
    """Capture one keyframe to JPEG; returns the path or None."""
    buf = bytearray()
    started = False
    t0 = time.monotonic()
    try:
        for frame in stream_h264(cfg.UID, cfg.CAMERA_IP, cfg.CLIENT_IP,
                                 password=cfg.VIEW_PW.encode(),
                                 broadcast=cfg.BROADCAST):
            if not started:
                if not _has_sps(frame):
                    continue
                started = True
            buf += frame
            if len(buf) > 200000 or time.monotonic() - t0 > 15:
                break
    except Exception as e:  # noqa: BLE001
        print(f"  stream error: {e}")
        return None
    raw, jpg = f"{OUT}/focus_{tag}.h264", f"{OUT}/focus_{tag}.jpg"
    open(raw, "wb").write(bytes(buf))
    subprocess.run([FF, "-y", "-loglevel", "error", "-f", "h264", "-i", raw,
                    "-frames:v", "1", jpg], capture_output=True)
    return jpg if os.path.exists(jpg) and os.path.getsize(jpg) else None


def main() -> None:
    print("FOCUS ASSIST — rotate the lens SLOWLY; watch for the score to PEAK.")
    print("Point the camera at a detailed subject at the distance you care about.\n")
    best = (0.0, None)
    t0 = time.monotonic()
    i = 0
    while time.monotonic() - t0 < TOTAL:
        i += 1
        jpg = grab(str(i % 2))
        if not jpg:
            continue
        s = sharpness(jpg)
        if s > best[0]:
            best = (s, i)
        bar = "#" * min(60, int(s / 2))
        star = "  <<< BEST SO FAR" if best[1] == i else ""
        print(f"  [{i:3}] sharpness {s:8.1f} {bar}{star}", flush=True)
        time.sleep(max(0.0, PER - 2))
    print(f"\nbest score {best[0]:.1f} (sample #{best[1]}) — leave the lens where the number peaked.")


if __name__ == "__main__":
    main()
