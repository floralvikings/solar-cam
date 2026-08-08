#!/usr/bin/env python3
"""Capture UART output to a log file (and echo decoded text).
Usage: serial_capture.py [port] [baud] [seconds] [logfile]
"""
import sys, time, serial

port = sys.argv[1] if len(sys.argv) > 1 else "/dev/cu.usbserial-0001"
baud = int(sys.argv[2]) if len(sys.argv) > 2 else 115200
dur = float(sys.argv[3]) if len(sys.argv) > 3 else 150.0
log = sys.argv[4] if len(sys.argv) > 4 else "/Users/cbrinkman/.claude/jobs/0eb50487/tmp/boot.log"

# rtscts/dsrdtr off; only GND/TX/RX are wired, so no reset lines involved.
ser = serial.Serial(port, baud, timeout=0.2, rtscts=False, dsrdtr=False)
print(f"capturing {port} @ {baud} for {dur:.0f}s -> {log}\n(power on the camera now)\n", flush=True)
t0 = time.monotonic()
total = 0
with open(log, "wb", buffering=0) as f:
    while time.monotonic() - t0 < dur:
        data = ser.read(4096)
        if data:
            f.write(data)
            total += len(data)
            try:
                sys.stdout.write(data.decode("utf-8", "replace"))
                sys.stdout.flush()
            except Exception:
                pass
ser.close()
print(f"\n[captured {total} bytes in {dur:.0f}s]", flush=True)
