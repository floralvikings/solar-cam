"""Per-camera device: registers the capture pipeline with go2rtc and exposes
an RTSP URL that Home Assistant's native stream + go2rtc can both open.

Home Assistant's native ``stream`` worker (PyAV) cannot open a go2rtc ``exec:``
source (``Protocol not found``), so we register that exec source with go2rtc's
REST API under a stream name and return ``rtsp://127.0.0.1:<port>/<name>``.
go2rtc runs the capture pipeline (capture.py -> ffmpeg -> go2rtc) on demand and
serves plain RTSP that both go2rtc and HA's native stream can consume.

Registration is done lazily (on first stream request) rather than at setup:
go2rtc is a subprocess of HA Core and may not have bound its ports yet during
integration setup, but it is always up by the time a stream is requested.
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
        self._stream_url: str | None = None
        self._lock = asyncio.Lock()

    def _exec_source(self) -> str:
        py = sys.executable or "python3"
        pipeline = (
            f"{py} {_CAPTURE} --uid {self.uid} "
            f"--camera-ip {self.host} --client-ip {self.client_ip} -o - | {_FFMPEG}"
        )
        return "exec:sh -c " + shlex.quote(pipeline)

    async def async_stream_url(self) -> str | None:
        """Ensure the go2rtc stream is registered and return its RTSP URL.

        Called when HA requests the stream. Returns None (camera shows
        unavailable) if go2rtc cannot be reached, and retries on next request.
        """
        if self._stream_url:
            return self._stream_url
        async with self._lock:
            if self._stream_url:
                return self._stream_url
            session = async_get_clientsession(self.hass)
            if not await self._register(session):
                _LOGGER.warning(
                    "Could not reach go2rtc at %s to register the stream. "
                    "Is go2rtc enabled in Home Assistant? (Settings > Devices & "
                    "Services should list a 'go2rtc' integration.)",
                    GO2RTC_API,
                )
                return None
            rtsp_port = await self._discover_rtsp_port(session)
            self._stream_url = f"rtsp://127.0.0.1:{rtsp_port}/{self.stream_name}"
            _LOGGER.debug("registered go2rtc stream, URL: %s", self._stream_url)
        return self._stream_url

    async def _register(self, session) -> bool:
        src = self._exec_source()
        for _ in range(3):
            try:
                async with session.put(
                    f"{GO2RTC_API}/api/streams",
                    params={"name": self.stream_name, "src": src},
                ) as resp:
                    if resp.status < 400:
                        return True
                    _LOGGER.debug("go2rtc PUT returned %s", resp.status)
            except Exception as err:  # noqa: BLE001 - go2rtc may be briefly down
                _LOGGER.debug("go2rtc not reachable (%s)", err)
            await asyncio.sleep(1)
        return False

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
