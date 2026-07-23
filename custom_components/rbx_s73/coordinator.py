"""Per-camera device: owns the shared MJPEG pipeline for one RBX-S73.

Self-contained, no go2rtc: the camera's H.264 is captured by the vendored
``capture.py`` (pure-Python P4P client) and transcoded to MJPEG by ffmpeg,
which Home Assistant serves natively (live MJPEG + snapshots). Everything runs
on the HA host on the local LAN; no cloud.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import shlex
import sys

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import CONF_CLIENT_IP, CONF_HOST, CONF_UID
from .stream import CameraStream

_LOGGER = logging.getLogger(__name__)

_CAPTURE = os.path.join(os.path.dirname(__file__), "capture.py")

# ffmpeg: raw Annex-B H.264 on stdin -> mpjpeg (motion-JPEG) on stdout at 10fps.
_FFMPEG = (
    "ffmpeg -hide_banner -loglevel error -fflags nobuffer "
    "-f h264 -i pipe:0 -f mpjpeg -q:v 5 -r 10 pipe:1"
)


def _subnet_broadcast(ip: str, prefix: int = 24) -> str:
    try:
        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        return str(net.broadcast_address)
    except ValueError:
        return "255.255.255.255"


class RbxS73Device:
    """Holds config + the shared MJPEG stream for one camera."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.host: str = entry.data[CONF_HOST]
        self.uid: str = entry.data[CONF_UID]
        self.client_ip: str = entry.data[CONF_CLIENT_IP]
        self.entry_id: str = entry.entry_id
        self.stream = CameraStream(self._mjpeg_cmd)

    def _mjpeg_cmd(self) -> str:
        py = sys.executable or "python3"
        broadcast = _subnet_broadcast(self.client_ip)
        capture = (
            f"{shlex.quote(py)} {shlex.quote(_CAPTURE)} "
            f"--uid {shlex.quote(self.uid)} "
            f"--camera-ip {shlex.quote(self.host)} "
            f"--client-ip {shlex.quote(self.client_ip)} "
            f"--broadcast {shlex.quote(broadcast)} -o -"
        )
        return f"{capture} | {_FFMPEG}"

    async def async_stop(self) -> None:
        await self.stream.stop()
