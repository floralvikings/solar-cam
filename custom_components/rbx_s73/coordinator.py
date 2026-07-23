"""Per-camera device: registers the capture pipeline with go2rtc and exposes
an RTSP URL that Home Assistant's native stream + go2rtc can both open.

Home Assistant's native `stream` worker (PyAV) cannot open a go2rtc `exec:`
source, so we register that exec source with go2rtc's REST API under a stream
name and return ``rtsp://127.0.0.1:<port>/<name>``. go2rtc runs the capture
pipeline (capture.py -> ffmpeg -> go2rtc) on demand and serves plain RTSP.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shlex
import sys

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import CONF_CLIENT_IP, CONF_HOST, CONF_UID

_LOGGER = logging.getLogger(__name__)

_CAPTURE = os.path.join(os.path.dirname(__file__), "capture.py")

# HA's bundled go2rtc runs its REST API on localhost:1984 (same container).
GO2RTC_API = "http://127.0.0.1:1984"

# capture.py -> stdout (Annex-B H.264) | ffmpeg -> go2rtc's RTSP ingest ({output}).
_FFMPEG = (
    "ffmpeg -hide_banner -loglevel error -fflags nobuffer "
    "-f h264 -framerate 15 -i pipe:0 -c copy -rtsp_transport tcp -f rtsp {output}"
)


class RbxS73Device:
    """Owns a camera's go2rtc stream registration + its RTSP URL."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.host: str = entry.data[CONF_HOST]
        self.uid: str = entry.data[CONF_UID]
        self.client_ip: str = entry.data[CONF_CLIENT_IP]
        self.entry_id: str = entry.entry_id
        self.stream_name = f"rbx_s73_{self.uid.lower()}"
        self._rtsp_url: str | None = None

    def _exec_source(self) -> str:
        py = sys.executable or "python3"
        pipeline = (
            f"{py} {_CAPTURE} --uid {self.uid} "
            f"--camera-ip {self.host} --client-ip {self.client_ip} -o - | {_FFMPEG}"
        )
        return "exec:sh -c " + shlex.quote(pipeline)

    async def async_setup(self) -> None:
        """Register the exec source with go2rtc and resolve the RTSP URL."""
        session = async_get_clientsession(self.hass)
        src = self._exec_source()
        registered = False
        for attempt in range(6):
            try:
                async with session.put(
                    f"{GO2RTC_API}/api/streams",
                    params={"name": self.stream_name, "src": src},
                ) as resp:
                    if resp.status < 400:
                        registered = True
                        break
                    _LOGGER.debug("go2rtc PUT status %s", resp.status)
            except Exception as err:  # noqa: BLE001 - go2rtc may not be up yet
                _LOGGER.debug("go2rtc not ready (%s), retrying", err)
            await asyncio.sleep(2)
        if not registered:
            _LOGGER.warning(
                "Could not register stream with go2rtc at %s; is go2rtc enabled?",
                GO2RTC_API,
            )

        rtsp_port = await self._discover_rtsp_port(session)
        self._rtsp_url = f"rtsp://127.0.0.1:{rtsp_port}/{self.stream_name}"
        _LOGGER.debug("stream URL: %s", self._rtsp_url)

    async def _discover_rtsp_port(self, session) -> int:
        try:
            async with session.get(f"{GO2RTC_API}/api") as resp:
                cfg = await resp.json(content_type=None)
            listen = ((cfg or {}).get("rtsp") or {}).get("listen") or ":8554"
            return int(str(listen).rsplit(":", 1)[-1])
        except Exception:  # noqa: BLE001
            return 8554

    async def async_teardown(self) -> None:
        session = async_get_clientsession(self.hass)
        try:
            await session.delete(
                f"{GO2RTC_API}/api/streams", params={"src": self.stream_name}
            )
        except Exception:  # noqa: BLE001
            pass

    def stream_source(self) -> str | None:
        return self._rtsp_url
