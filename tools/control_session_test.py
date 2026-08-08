#!/usr/bin/env python3
"""Validate p4p.client.LanControlSession end-to-end against the real camera:
run the video+control session, then drive PTZ through its Unix control socket
exactly the way the HA integration will. Confirms video keeps flowing and the
ioctrl handshake completes. Config from env/local/device.json. Camera FREE.
"""
import os, sys, time, socket, threading
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p4p_probe_config as cfg
from p4p.client import LanControlSession

SOCK = "/Users/cbrinkman/.claude/jobs/0eb50487/tmp/rbx_ctrl_test.sock"

def main():
    sess = LanControlSession(cfg.UID, cfg.CAMERA_IP, cfg.CLIENT_IP,
                             password=cfg.VIEW_PW.encode(), broadcast=cfg.BROADCAST,
                             control_sock_path=SOCK)
    frames = [0]; keyframe = [False]; stop = threading.Event()
    def run():
        try:
            for f in sess.frames():
                frames[0] += 1
                if not keyframe[0]: keyframe[0] = True; print(f"[video] first keyframe ({len(f)}B)")
                if stop.is_set(): break
        except Exception as e:
            print(f"[session] ended: {e}")
    th = threading.Thread(target=run, daemon=True); th.start()

    # wait for the control socket + ioctrl-ready
    t = time.monotonic() + 30
    while time.monotonic() < t and not (os.path.exists(SOCK) and sess.ioctrl_ready):
        time.sleep(0.3)
    print(f"[status] socket={os.path.exists(SOCK)} ioctrl_ready={sess.ioctrl_ready} frames={frames[0]}")
    if not sess.ioctrl_ready:
        print("!! ioctrl handshake did not complete"); stop.set(); return

    c = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    def cmd(t):
        c.sendto(t.encode(), SOCK); print(f"[ctrl] -> {t!r}")
    print("\n### WATCH THE CAMERA — LEFT, RIGHT, each ~3s via the HA control path ###\n")
    for d in ("left", "right", "left", "right"):
        cmd(f"ptz {d}"); time.sleep(3.0); cmd("ptz stop"); time.sleep(1.5)
    print(f"\n[done] video frames received during test: {frames[0]} (video stayed alive: {frames[0] > 0})")
    stop.set(); time.sleep(0.5)

main()
