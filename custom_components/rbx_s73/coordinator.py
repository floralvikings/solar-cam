"""Per-camera device: config + the go2rtc exec stream source.

With go2rtc owning the single AV session (it exec's capture.py), the integration
itself does not open a session -- it just builds the go2rtc source string and
provides device metadata.
"""

from __future__ import annotations

import os
import shlex
import sys

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import CONF_CLIENT_IP, CONF_HOST, CONF_UID

_CAPTURE = os.path.join(os.path.dirname(__file__), "capture.py")

# capture.py -> stdout (Annex-B H.264) | ffmpeg -> go2rtc's RTSP publish ({output}).
_FFMPEG = (
    "ffmpeg -hide_banner -loglevel error -fflags nobuffer "
    "-f h264 -framerate 15 -i pipe:0 -c copy -rtsp_transport tcp -f rtsp {output}"
)


class RbxS73Device:
    """Holds a camera's config and produces its go2rtc stream source."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.host: str = entry.data[CONF_HOST]
        self.uid: str = entry.data[CONF_UID]
        self.client_ip: str = entry.data[CONF_CLIENT_IP]
        self.entry_id: str = entry.entry_id

    def go2rtc_source(self) -> str:
        """Return an ``exec:`` go2rtc source that runs capture.py -> ffmpeg -> RTSP.

        go2rtc substitutes ``{output}`` with its internal RTSP publish URL.
        """
        py = sys.executable or "python3"
        capture = (
            f"{shlex.quote(py)} {shlex.quote(_CAPTURE)} "
            f"--uid {shlex.quote(self.uid)} "
            f"--camera-ip {shlex.quote(self.host)} "
            f"--client-ip {shlex.quote(self.client_ip)} -o -"
        )
        pipeline = f"{capture} | {_FFMPEG}"
        return "exec:sh -c " + shlex.quote(pipeline)
