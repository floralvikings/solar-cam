"""Ask the vendor's update service what firmware it would serve this camera.

This is the normal client update-check, reproduced outside the app so the
offered image can be fetched and validated with ``scripts/ota_image.py``.

Why it needs a lever: the device is already on the newest build, and the service
only returns image metadata when it considers the caller out of date — that is
the "no OTA for an up-to-date device" dead end recorded in
docs/capture-procedure.md. Passing an older ``--host-version`` asks the same
question an older camera would ask, which should make the service name the
*current* image. That image is the one we want: it can be checked against the
32-byte container format and byte-compared with the mtd3/mtd4 regions of the
flash dump we already have.

Endpoints (from ``NewApiHttpClient``)::

    v2  POST https://portal.ubianet.com/api/v2/user/check_version
    v3  POST https://portal.ubianet.com/api/v3/user/qry/device/check_version/v3

Both send ``X-Ubia-Auth-UserToken``. Supply it with --token or RBX_USER_TOKEN;
capture one per docs/capture-procedure.md (mitmproxy + WireGuard). The UID comes
from local/device.json and is redacted in this tool's output.

Usage::

    .venv/bin/python tools/ota_check.py --host-version 2455.0.0.1
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, "tools")

import p4p_probe_config as cfg  # noqa: E402

V2_URL = "https://portal.ubianet.com/api/v2/user/check_version"
V3_URL = "https://portal.ubianet.com/api/v3/user/qry/device/check_version/v3"
CALL_CONTEXT = ("source=app&app=ubox&ver=5.0.0&osver=13&region=US"
                "&os=android&uuid=&lang=en")
CURRENT_VERSION = "2455.0.21.10"


def redact(uid: str) -> str:
    return f"{uid[:4]}…{uid[-4:]}" if len(uid) > 8 else "…"


def pkid_for(version: str) -> str:
    """``(packed_version & 0xff000000) >> 24``, wrapped to 0..255.

    The app packs "a.b.c.d" as (a<<24)|(b<<16)|(c<<8)|d in a *signed* 32-bit
    int, takes the top byte, then adds 256 if it went negative
    (AdvancedSettings.getLastVersion). For 2455.0.21.10 that lands on 151.
    """
    head = int(version.split(".")[0])
    packed = (head << 24) & 0xFFFFFFFF
    top = (packed >> 24) & 0xFF
    return str(top)


def post(url: str, body: dict, token: str | None, timeout: float) -> tuple[int, str]:
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-UbiaAPI-CallContext", CALL_CONTEXT)
    req.add_header("User-Agent", "okhttp/3.12.1")
    if token:
        req.add_header("X-Ubia-Auth-UserToken", token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host-version", default=CURRENT_VERSION,
                    help=f"version to claim (default {CURRENT_VERSION}, the real one)")
    ap.add_argument("--pkid", default=None,
                    help="product-kind id; default = the version's first octet")
    ap.add_argument("--product-id", default="")
    ap.add_argument("--token", default=os.environ.get("RBX_USER_TOKEN"),
                    help="X-Ubia-Auth-UserToken (or set RBX_USER_TOKEN)")
    ap.add_argument("--zone-id", type=int, default=0)
    ap.add_argument("--api", choices=("v2", "v3", "both"), default="both")
    ap.add_argument("--timeout", type=float, default=20.0)
    args = ap.parse_args()

    uid = cfg.UID
    pkid = args.pkid if args.pkid is not None else pkid_for(args.host_version)
    print(f"uid={redact(uid)}  host_version={args.host_version}  pkid={pkid}  "
          f"token={'yes' if args.token else 'NONE'}\n")

    body_v2 = {
        "device_uid": uid,
        "host_version": args.host_version,
        "wifi_version": args.host_version,
        "pkid": pkid,
        "product_id": args.product_id,
        "token": args.token or "",
        "zone_id": args.zone_id,
    }
    targets = []
    if args.api in ("v2", "both"):
        targets.append(("v2", V2_URL, body_v2))
    if args.api in ("v3", "both"):
        targets.append(("v3", V3_URL, dict(body_v2, uid=uid)))

    for name, url, body in targets:
        print(f"--- {name}  POST {url}")
        try:
            status, text = post(url, body, args.token, args.timeout)
        except (urllib.error.URLError, OSError) as exc:
            print(f"    network error: {exc}\n")
            continue
        print(f"    HTTP {status}")
        try:
            parsed = json.loads(text)
        except ValueError:
            print(f"    {text[:600]}\n")
            continue
        print("    " + json.dumps(parsed, indent=2).replace("\n", "\n    ")[:2000] + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
