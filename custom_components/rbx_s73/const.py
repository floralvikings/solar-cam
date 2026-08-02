"""Constants for the RBX-S73 camera integration."""

from __future__ import annotations

DOMAIN = "rbx_s73"

CONF_HOST = "host"          # camera IP
CONF_UID = "uid"            # 20-char device UID
CONF_CLIENT_IP = "client_ip"  # this HA host's LAN IP (video destination)

# The camera only serves one AV session at a time; the integration owns it.
LAN_SEARCH_PORT = 32762

# --- PTZ controls (ioctrl over the live session) ---
# The camera runs one session, so PTZ rides the active video session via a Unix
# control socket into the capture subprocess. Directions map to ENUM_PTZCMD.
PTZ_DIRECTIONS = {
    "left": "mdi:arrow-left-bold",
    "right": "mdi:arrow-right-bold",
    "up": "mdi:arrow-up-bold",
    "down": "mdi:arrow-down-bold",
}
# A press = a nudge: repeat the direction command every PTZ_REPEAT_INTERVAL for
# PTZ_NUDGE_SECONDS, then stop. The motor moves a small step/burst per command
# (that's how repeated commands walked it to its limit in testing), so a single
# command is imperceptible — repeating accumulates a visible move. Press again to
# move further; the whole PTZ range was ~10 commands.
PTZ_NUDGE_SECONDS = 1.0
PTZ_REPEAT_INTERVAL = 0.3


def control_sock_path(uid: str) -> str:
    """Per-camera Unix control socket (capture.py binds it, HA writes to it)."""
    import tempfile

    return f"{tempfile.gettempdir()}/rbx_s73_{uid}.sock"

# --- Time-lapse options (config entry options) ---
CONF_TL_RATE = "timelapse_rate"              # how many frames to capture per unit
CONF_TL_RATE_UNIT = "timelapse_rate_unit"    # "minute" | "hour" | "day"
CONF_TL_FPS = "timelapse_fps"                # output video frame rate
CONF_TL_DIR = "timelapse_dir"                # base output directory
CONF_TL_KEEP_FRAMES = "timelapse_keep_frames"  # keep JPEGs after compiling
CONF_TL_COMPILE_HOUR = "timelapse_compile_hour"  # daily auto-compile hour; <0 off

# capture rate -> interval: seconds_in(unit) / rate
TL_UNIT_SECONDS = {"minute": 60, "hour": 3600, "day": 86400}
TL_MIN_INTERVAL_SECONDS = 5  # floor (a capture wakes the camera ~10s)

DEFAULT_TL_RATE = 4            # 4 frames/hour = one every 15 min
DEFAULT_TL_RATE_UNIT = "hour"
DEFAULT_TL_FPS = 24
DEFAULT_TL_DIR = "/media/rbx_s73"
DEFAULT_TL_KEEP_FRAMES = True  # keep frames by default; uncheck to reclaim space
DEFAULT_TL_COMPILE_HOUR = 0

# On-demand range exports are temporary: auto-deleted after this many hours.
EXPORT_TTL_HOURS = 6

# --- Session model (how the single camera session is kept) ---
CONF_SESSION_MODE = "session_mode"
SESSION_MODE_SOLAR = "solar"          # permanent while sun is up, keep-warm at night
SESSION_MODE_PERMANENT = "permanent"  # always on (auto-reconnect)
SESSION_MODE_KEEP_WARM = "keep_warm"  # hold a few min after use, then sleep
SESSION_MODE_ON_DEMAND = "on_demand"  # sleep between uses (most battery-friendly)
SESSION_MODES = [
    SESSION_MODE_SOLAR,
    SESSION_MODE_PERMANENT,
    SESSION_MODE_KEEP_WARM,
    SESSION_MODE_ON_DEMAND,
]
DEFAULT_SESSION_MODE = SESSION_MODE_SOLAR
