# UBox APK Analysis — RBX-S73

Goal: identify the bundled native P2P SDK, the API endpoints, the command IDs
for pan/tilt/live/playback, and the obfuscation/key-derivation routine — to
shortcut the payload reverse-engineering.

> Only analyze an APK from **your own device and account**. APKs and everything
> decompiled from them are **git-ignored** (`apk/`, `jadx-output/`, `*.so`).

Tooling installed: `jadx` 1.5.6, `apktool` 3.0.3, `adb` 1.0.41.

## 1. Obtain the APK from your own phone

```bash
# Enable Developer options -> USB debugging on the phone, connect via USB
adb devices                     # authorize the prompt on the phone

# Find the package (try both names)
adb shell pm list packages | grep -iE 'ubox|ubia'

# Get its APK path(s)
adb shell pm path <package.name>
```

⚠️ **Modern apps are split APKs.** `pm path` often returns several lines:
`base.apk` plus `split_config.arm64_v8a.apk`, `split_config.xxhdpi.apk`, etc.
**The native P2P SDK lives in the ABI split**, not `base.apk` — pull them all:

```bash
mkdir -p apk
adb shell pm path <package.name> | sed 's/^package://' | while read -r p; do
    adb pull "$p" "apk/$(basename "$p")"
done
ls -la apk/
```

## 2. Run the recon harness

```bash
export PATH="/opt/homebrew/bin:$PATH"

# base.apk -> Java sources, endpoints, command constants
.venv/bin/python scripts/apk_recon.py --apk apk/base.apk --apktool

# the ABI split -> the native .so libraries (where the SDK is)
.venv/bin/python scripts/apk_recon.py --apk apk/split_config.arm64_v8a.apk \
    --out apk/native --apktool

# re-scan later without the slow jadx step
.venv/bin/python scripts/apk_recon.py --apk apk/base.apk --skip-decompile
```

`scripts/apk_recon.py` reports:
- **Bundled P2P SDK candidates** (TUTK/Kalay, CS2 PPPP, Tuya, Ayla, HiChip,
  Yoosee, iCSee, UBIA) matched against lib names + native strings
- **Native libraries** and their string counts
- **Hostnames** found in Java sources *and* inside the `.so` files
  (vendor hits flagged `<== VENDOR`)
- **Command/opcode constants** (`IOTYPE_*`, `CMD_*`, `MSG_*`, `AVIOCTRL*`)
- **Keyword hit counts** (rtsp, onvif, stun, p2p, ota, aes, xor, ...)

## 3. What we're hoping to find

| Question | What would answer it |
|----------|----------------------|
| Which SDK? | `libIOTCAPIs.so`/`avClientStart` → TUTK; `libPPPP.so`/`PPCS_*` → CS2 |
| Command IDs | A `IOTYPE_USER_IPCAM_*` / `AVIOCTRLDEFs` table gives pan/tilt/live opcodes outright |
| Obfuscation | The XOR/mask routine that produces the `54a58d…`/`14a09d…` headers (see `protocol-notes.md`) |
| Endpoints | `portal.us.ubianet.com` API paths, login/registration flow |
| Device UID format | How the UID in the packet header is derived |
| OTA | Firmware update-check URL → gets us an image without hardware work |

**Important:** do not assume the Java code holds the protocol logic. In this
class of app it is almost always in a bundled proprietary **native** SDK —
which is why we scan `.so` strings too.

## 4. If the code is obfuscated / pinned

- Java heavily ProGuard'd → pivot to the native libs (`nm -D`, `readelf -Ws`).
- If we later want to observe the HTTPS API, first check for certificate
  pinning, then mitmproxy/Burp (own device + account only). Note the *camera's*
  own control traffic is **not** TLS (see `protocol-notes.md`), so the app's
  HTTPS API is a separate, smaller surface.

## Findings

_(populate after the first run)_

- Package name: _TBD_
- App version: _TBD_
- Native libs: _TBD_
- **SDK identified:** _TBD_
- API endpoints: _TBD_
- Command IDs: _TBD_
- Obfuscation routine: _TBD_
- OTA endpoint: _TBD_
