#!/usr/bin/env python3
"""Try several baud rates on the live UART; report which yields readable ASCII.
Needs the camera to be OUTPUTTING during the sweep (boot or ongoing logs).
"""
import serial, time, sys

port = sys.argv[1] if len(sys.argv) > 1 else "/dev/cu.usbserial-0001"
win = float(sys.argv[2]) if len(sys.argv) > 2 else 3.0
bauds = [115200, 57600, 38400, 19200, 9600, 230400, 460800, 74880, 250000]
print(f"sweeping {port}, {win:.0f}s per baud\n", flush=True)
best = None
for b in bauds:
    try:
        ser = serial.Serial(port, b, timeout=0.2, rtscts=False, dsrdtr=False)
    except Exception as e:
        print(f"{b:>7}: open error {e}", flush=True); continue
    ser.reset_input_buffer()
    data = b""
    t = time.monotonic()
    while time.monotonic() - t < win:
        data += ser.read(8192)
    ser.close()
    n = len(data)
    printable = sum(1 for c in data if 9 <= c <= 13 or 32 <= c <= 126)
    ratio = (printable / n * 100) if n else 0.0
    sample = data[:70].decode("latin1", "replace").replace("\n", " ").replace("\r", " ")
    print(f"{b:>7}: {n:5}B  {ratio:5.1f}% printable | {sample!r}", flush=True)
    if n > 20 and ratio > (best[1] if best else 60):
        best = (b, ratio)
print(f"\nbest guess: {best[0] if best else 'none — camera not outputting; power-cycle during the sweep'}", flush=True)
