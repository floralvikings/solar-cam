#!/usr/bin/env python3
"""Attach Frida to the UBox gadget and stream the hook's output.

Runs for a fixed window so the operator can log in and open live view; prints
every hooked packet (see tools/hook.js). Captured device secrets stay in this
console output only -- do NOT commit them.
"""
import sys, time, frida

DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 240

dev = frida.get_usb_device(timeout=5)
# Wait for the gadget to come up (app may still be launching).
session = None
for _ in range(40):
    try:
        session = dev.attach("Gadget")
        break
    except frida.ProcessNotFoundError:
        time.sleep(0.5)
if session is None:
    print("ERROR: Gadget process not found (is UBox running?)", flush=True)
    sys.exit(1)
with open("tools/hook.js") as f:
    src = f.read()
script = session.create_script(src)

def on_message(msg, data):
    t = msg.get("type")
    if t == "log":
        print(msg["payload"], flush=True)
    elif t == "send":
        print("SEND:", msg["payload"], flush=True)
    elif t == "error":
        print("ERROR:", msg.get("stack") or msg, flush=True)
    else:
        print(msg, flush=True)

script.on("message", on_message)
script.load()
print(f"[hook attached] LOG IN to UBox and OPEN the camera's LIVE VIEW now. "
      f"Listening {DURATION}s...", flush=True)
end = time.time() + DURATION
while time.time() < end:
    time.sleep(1)
print("[done listening]", flush=True)
