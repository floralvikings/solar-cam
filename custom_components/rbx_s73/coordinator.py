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
from homeassistant.helpers.event import async_track_sunrise, async_track_sunset

from .const import (
    CONF_CLIENT_IP,
    CONF_HOST,
    CONF_SESSION_MODE,
    CONF_UID,
    DEFAULT_SESSION_MODE,
    SESSION_MODE_KEEP_WARM,
    SESSION_MODE_ON_DEMAND,
    SESSION_MODE_PERMANENT,
    SESSION_MODE_SOLAR,
)
from .stream import CameraStream

_LOGGER = logging.getLogger(__name__)

_KEEPWARM_IDLE = 300.0  # keep-warm: hold the session 5 min after last use
_ONDEMAND_IDLE = 8.0

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
        self.entry = entry
        self.stream = CameraStream(self._mjpeg_cmd)
        self.timelapse = None  # set by __init__.async_setup_entry
        self._unsub_sun: list = []

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

    # ---- session model ------------------------------------------------
    def _session_mode(self) -> str:
        return self.entry.options.get(CONF_SESSION_MODE, DEFAULT_SESSION_MODE)

    def _sun_is_up(self) -> bool:
        state = self.hass.states.get("sun.sun")
        return state is not None and state.state == "above_horizon"

    async def async_apply_session_mode(self) -> None:
        """Configure how the single camera session is kept, per the option."""
        await self._clear_sun_tracking()
        mode = self._session_mode()

        if mode == SESSION_MODE_ON_DEMAND:
            self.stream.set_idle_hold(_ONDEMAND_IDLE)
            await self.stream.set_permanent(False)
        elif mode == SESSION_MODE_KEEP_WARM:
            self.stream.set_idle_hold(_KEEPWARM_IDLE)
            await self.stream.set_permanent(False)
        elif mode == SESSION_MODE_PERMANENT:
            await self.stream.set_permanent(True)
        elif mode == SESSION_MODE_SOLAR:
            # permanent while the sun is up (solar charging offsets the drain),
            # keep-warm after sunset. sun.sun drives the transitions.
            self.stream.set_idle_hold(_KEEPWARM_IDLE)
            if self.hass.states.get("sun.sun") is None:
                _LOGGER.warning(
                    "session_mode 'solar' needs the sun integration; "
                    "falling back to keep-warm"
                )
                await self.stream.set_permanent(False)
                return
            await self.stream.set_permanent(self._sun_is_up())
            self._unsub_sun = [
                async_track_sunrise(self.hass, self._on_sunrise),
                async_track_sunset(self.hass, self._on_sunset),
            ]

    async def _on_sunrise(self) -> None:
        if self._session_mode() == SESSION_MODE_SOLAR:
            _LOGGER.debug("sunrise: switching camera to permanent session")
            await self.stream.set_permanent(True)

    async def _on_sunset(self) -> None:
        if self._session_mode() == SESSION_MODE_SOLAR:
            _LOGGER.debug("sunset: switching camera to keep-warm")
            await self.stream.set_permanent(False)

    async def _clear_sun_tracking(self) -> None:
        for unsub in self._unsub_sun:
            unsub()
        self._unsub_sun = []

    async def async_stop(self) -> None:
        await self._clear_sun_tracking()
        await self.stream.set_permanent(False)
        await self.stream.stop()
