#!/usr/bin/env python3
"""UART capture + U-Boot interrupt/command helper for the RBX-S73 (Ingenic T23).

The stock bootloader has bootdelay=1, so to reach the U-Boot prompt you must be
spamming a key the instant power is applied. Modes:

  capture  PORT SECS LOG            passively log the boot output
  break    PORT SECS LOG            spam keys to interrupt autoboot, then log
  cmd      PORT "CMD" SECS LOG      send one command (at an existing prompt), log reply

Serial is 115200 8N1 (confirmed from the firmware: console=ttyS0,115200n8).
Only ONE process may hold the port -- check with `lsof <port>`.
"""
import sys, time, serial

def run(mode, port, arg, secs, log):
    ser = serial.Serial(port, 115200, timeout=0.1, rtscts=False, dsrdtr=False)
    ser.reset_input_buffer()
    t0 = time.monotonic()
    last_spam = 0.0
    sent = False
    total = 0
    with open(log, "wb", buffering=0) as f:
        while time.monotonic() - t0 < secs:
            now = time.monotonic()
            if mode == "break" and now - last_spam > 0.02:
                # any key stops autoboot; space is harmless at a shell prompt too
                ser.write(b" ")
                last_spam = now
            if mode == "cmd" and not sent:
                ser.write(arg.encode() + b"\r\n")
                sent = True
            data = ser.read(4096)
            if data:
                f.write(data)
                total += len(data)
                sys.stdout.write(data.decode("utf-8", "replace"))
                sys.stdout.flush()
            # once we've seen a prompt in break mode, stop spamming so we can type
            if mode == "break" and total and b"#" in data:
                mode = "hold"
    ser.close()
    print(f"\n[captured {total} bytes -> {log}]", flush=True)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__); raise SystemExit(1)
    mode = sys.argv[1]
    if mode in ("capture", "break"):
        port = sys.argv[2]; secs = float(sys.argv[3]); log = sys.argv[4]
        run(mode, port, None, secs, log)
    elif mode == "cmd":
        port = sys.argv[2]; cmd = sys.argv[3]; secs = float(sys.argv[4]); log = sys.argv[5]
        run("cmd", port, cmd, secs, log)
    else:
        print(__doc__); raise SystemExit(1)
