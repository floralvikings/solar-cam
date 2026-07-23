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

## Findings (2026-07-23)

- **Package:** `cn.ubia.ubox` — pulled from an owned Galaxy S23 Ultra.
  `base.apk` (60 MB) + `split_config.arm64_v8a.apk` (90 MB) + en/xxhdpi splits.

### SDK identified: **rebranded ThroughTek TUTK** — **Confirmed**

Evidence (all from `libUBICAPIs.so`):
- `com/tutk/IOTC/st_LanSearchInfo2` — a **literal TUTK class path** left in the
  binary.
- JNI exports `Java_com_ubia_IOTC_IOTCAPIs_UBIC_1Lan_1Search2` etc. — TUTK's
  `IOTC_*` API mechanically renamed to `UBIC_*`, retaining `IOTC/IOTCAPIs`.
- `IOTC_ER_*` error codes in `UBICAPIs.java` match TUTK's published values
  (`IOTC_ER_ALREADY_INITIALIZED = -3`, `IOTC_ER_SERVER_NOT_RESPONSE = -1`, …).
- `av_client_*`, `IOTCVersion`, `NatType`, and the log format
  `STREAMREQ_COST: %u ms(P2P) UID:%s deviceSID:%d clientSID:%d`.

This matters enormously: the TUTK/Kalay IOTC + AVAPI protocol is publicly
documented and widely studied, so we are no longer reversing a black box.

### Native libraries of interest
| Library | Role |
|---------|------|
| `libUBICAPIs.so` (+`23`,`29`) | **The P2P SDK** (TUTK fork) |
| `libUbiaDecoder31.so` | Vendor video decoder |
| `libUBIENotify.so` | Push/notification |
| `libffmpeg/libavcodec/libijkplayer` | Playback |
| `libWebRtc*.so`, `libSpeexDsp`, `libFdkAACCodec`, `libG726Android` | Audio / AEC |

### The `p4p` API surface (JNI, `com.ubia.p4p.UBICAPIs`)
```
p4p_mgmt_init / p4p_mgmt_exit / p4p_mgmt_setnetmode / p4p_mgmt_getnetmode
p4p_client_start(st_P4PClient, int) / p4p_client_stop
p4p_client_startvideo / stopvideo / startaudio / stopaudio
p4p_client_startspeak / stopspeak            (two-way audio)
p4p_client_send_ioctrl(sid, ch, type, byte[], len)   <- command channel
p4p_client_send_avcommand(sid, ch, stP4PAVCmd)
p4p_client_startlansearch / stoplansearch
p4p_client_randomID / p4p_netcheck / p4p_client_set_callback
```
Internal symbols reveal both sides of LAN discovery:
`p4p_client_send_lansearchreq`, `p4p_client_handle_lansearchrsp`,
**`p4p_device_handle_lansearchreq`**, `p4p_device_handle_preconnectreq`.

### 🔑 Local operation is a first-class SDK concept — **Strongly indicated**
```java
public static final int CLI_SESSION_LAN     = 5;   // LAN session
public static final int CLI_SESSION_P2P     = 4;
public static final int CLI_SESSION_WAKEUP  = 1;
public static final int CLI_WRONG_VIEWACCPWD = -2005;  // view account/password
```
The camera firmware runs the **device side** of this same SDK
(`p4p_device_handle_lansearchreq`), so it should answer a proprietary UDP LAN
discovery broadcast — which is why SSDP/ONVIF/mDNS probes found nothing.
Combined with `CLI_SESSION_LAN` and `p4p_mgmt_setnetmode`, a **cloud-free
local session looks achievable**. Not yet proven on this device.

### Command table: `com/ubia/IOTC/AVIOCTRLDEFs.java` (494 constants)

PTZ (payload to `send_ioctrl`):
| Command | ID | | Command | ID |
|---|---|---|---|---|
| `AVIOCTRL_PTZ_STOP` | 0 | | `AVIOCTRL_PTZ_RIGHT_UP` | 7 |
| `AVIOCTRL_PTZ_UP` | 1 | | `AVIOCTRL_PTZ_RIGHT_DOWN` | 8 |
| `AVIOCTRL_PTZ_DOWN` | 2 | | `AVIOCTRL_PTZ_AUTO` | 9 |
| `AVIOCTRL_PTZ_LEFT` | 3 | | `AVIOCTRL_PTZ_SET_POINT` | 10 |
| `AVIOCTRL_PTZ_LEFT_UP` | 4 | | `AVIOCTRL_PTZ_GOTO_POINT` | 12 |
| `AVIOCTRL_PTZ_LEFT_DOWN` | 5 | | `AVIOCTRL_PTZ_START_CRUISE` | 38 |
| `AVIOCTRL_PTZ_RIGHT` | 6 | | `AVIOCTRL_PTZ_STOP_CRUISE` | 39 |

Also `AVIOCTRL_MOTOR_RESET_POSITION=35`, `AVIOCTRL_AUTO_PAN_START=29`.

Streaming / playback / files:
| Constant | ID |
|---|---|
| `IOTYPE_USER_IPCAM_SETSTREAMCTRL_REQ` / `_RESP` | 800 / 801 |
| `IOTYPE_USER_IPCAM_GETSTREAMCTRL_REQ` / `_RESP` | 802 / 803 |
| `IOTYPE_USER_IPCAM_GETSUPPORTSTREAM_REQ` / `_RESP` | 808 / 809 |
| `IOTYPE_USER_IPCAM_GETRECORD_REQ` / `_RESP` | 786 / 787 |
| `IOTYPE_USER_FILE_LIST_REQ` / `_RSP` | 4864 / 4865 |
| `IOTYPE_USER_FILE_DOWNLOAD_REQ` / `_RSP` | 4866 / 4867 |
| `IOTYPE_USER_EVENT_DOWNLOAD_REQ` / `_RSP` | 4876 / 4877 |
| `IOTYPE_UBIA_SET_UID_REQ` / `_RESP` | 241 / 242 |

Playback sub-commands: `RECORD_PLAY_START=16`, `STOP=1`, `PAUSE=0`,
`RESUME=8`, `SEEKTIME=6`, `FORWARD=4`, `BACKWARD=5`.

### Cloud endpoints (from the SDK binary)
- Portals: `portal.ubianet.com`, `portal.us.ubianet.com`, `portal.cn.ubianet.com`
- Ops: `oam.ubianet.com`; discovery/time: `d.ubianet.com`, `d.ntp.ubianet.com`
- **Media storage buckets** (regional): `ubiasnap-{as,eu,us}.oss-*.aliyuncs.com`
  and `ubiasnap-{as,eu,us}.s3-*.amazonaws.com` — where snapshots/clips land
  (matches the 336 KB idle upload in `protocol-notes.md`).
- `www.amazon.com` appears in the SDK → the connectivity-check loop is
  **baked into the SDK**, not the app.

### Still open
- Exact LAN-search UDP port + packet format (compiled-in ints, not strings) →
  get empirically by capturing the app doing a LAN search.
- Obfuscation/mask routine producing the `54a58d…`/`14a09d…` headers.
- OTA endpoint — not yet located.
