"""Time-lapse capture + compilation for one RBX-S73 camera.

Grabs a JPEG snapshot on a fixed interval (reusing the shared MJPEG session, so
it respects the one-session constraint) and, once a day, compiles the previous
day's frames into an H.264 mp4 with ffmpeg. On a solar/battery camera keep the
interval sane (each capture wakes the camera ~10s).

Layout under <dir>/<uid>/ :
    frames/<YYYYMMDD>/<HHMMSS>.jpg
    timelapse-<YYYYMMDD>.mp4
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import timedelta

from homeassistant.core import HomeAssistant
from homeassistant.helpers.event import (
    async_track_time_change,
    async_track_time_interval,
)
import homeassistant.util.dt as dt_util

from .const import (
    CONF_TL_COMPILE_HOUR,
    CONF_TL_DIR,
    CONF_TL_FPS,
    CONF_TL_KEEP_FRAMES,
    CONF_TL_RATE,
    CONF_TL_RATE_UNIT,
    DEFAULT_TL_COMPILE_HOUR,
    DEFAULT_TL_DIR,
    DEFAULT_TL_FPS,
    DEFAULT_TL_KEEP_FRAMES,
    DEFAULT_TL_RATE,
    DEFAULT_TL_RATE_UNIT,
    TL_MIN_INTERVAL_SECONDS,
    TL_UNIT_SECONDS,
)

_LOGGER = logging.getLogger(__name__)


class TimelapseManager:
    """Scheduled snapshot capture + daily compile for one camera."""

    def __init__(self, hass: HomeAssistant, device, entry) -> None:
        self.hass = hass
        self.device = device
        self.entry = entry
        self._unsub_interval = None
        self._unsub_daily = None
        self._busy = False
        self.enabled = False

    # ---- options ------------------------------------------------------
    def _opt(self, key, default):
        return self.entry.options.get(key, default)

    @property
    def rate(self) -> int:
        return max(1, int(self._opt(CONF_TL_RATE, DEFAULT_TL_RATE)))

    @property
    def rate_unit(self) -> str:
        unit = self._opt(CONF_TL_RATE_UNIT, DEFAULT_TL_RATE_UNIT)
        return unit if unit in TL_UNIT_SECONDS else DEFAULT_TL_RATE_UNIT

    @property
    def interval_seconds(self) -> float:
        """Seconds between captures, from 'rate' frames per 'rate_unit'."""
        return max(TL_MIN_INTERVAL_SECONDS, TL_UNIT_SECONDS[self.rate_unit] / self.rate)

    @property
    def fps(self) -> int:
        return int(self._opt(CONF_TL_FPS, DEFAULT_TL_FPS))

    @property
    def compile_hour(self) -> int:
        return int(self._opt(CONF_TL_COMPILE_HOUR, DEFAULT_TL_COMPILE_HOUR))

    @property
    def keep_frames(self) -> bool:
        return bool(self._opt(CONF_TL_KEEP_FRAMES, DEFAULT_TL_KEEP_FRAMES))

    @property
    def base_dir(self) -> str:
        root = self._opt(CONF_TL_DIR, DEFAULT_TL_DIR)
        return os.path.join(root, self.device.uid.lower())

    # ---- lifecycle ----------------------------------------------------
    async def async_start(self) -> None:
        if self.enabled:
            await self.async_reschedule()
            return
        self.enabled = True
        self._unsub_interval = async_track_time_interval(
            self.hass, self._on_interval, timedelta(seconds=self.interval_seconds)
        )
        if self.compile_hour >= 0:
            self._unsub_daily = async_track_time_change(
                self.hass, self._on_daily, hour=self.compile_hour, minute=5, second=0
            )
        _LOGGER.debug(
            "time-lapse started: %s frame(s)/%s (every %.0fs) -> %s",
            self.rate, self.rate_unit, self.interval_seconds, self.base_dir,
        )

    async def async_stop(self) -> None:
        self.enabled = False
        for unsub in (self._unsub_interval, self._unsub_daily):
            if unsub:
                unsub()
        self._unsub_interval = self._unsub_daily = None

    async def async_reschedule(self) -> None:
        """Re-apply interval/compile-hour after an options change (if running)."""
        if not self.enabled:
            return
        await self.async_stop()
        self.enabled = False
        await self.async_start()

    # ---- capture ------------------------------------------------------
    async def _on_interval(self, now) -> None:
        if self._busy:
            _LOGGER.debug("time-lapse: previous capture still running, skipping")
            return
        self._busy = True
        try:
            await self._capture_frame(now)
        except Exception as err:  # noqa: BLE001
            _LOGGER.warning("time-lapse capture failed: %s", err)
        finally:
            self._busy = False

    async def _capture_frame(self, now) -> None:
        jpeg = await self.device.stream.snapshot()
        if not jpeg:
            _LOGGER.debug("time-lapse: no frame from camera")
            return
        local = dt_util.as_local(now)
        day_dir = os.path.join(self.base_dir, "frames", local.strftime("%Y%m%d"))
        path = os.path.join(day_dir, local.strftime("%H%M%S") + ".jpg")
        await self.hass.async_add_executor_job(_write_file, day_dir, path, jpeg)
        _LOGGER.debug("time-lapse frame -> %s", path)

    # ---- compile ------------------------------------------------------
    async def _on_daily(self, now) -> None:
        yesterday = (dt_util.as_local(now) - timedelta(days=1)).strftime("%Y%m%d")
        await self.async_compile(yesterday)

    async def async_compile(self, date: str | None = None) -> str | None:
        """Compile a day's frames (YYYYMMDD, default today) into an mp4."""
        if date is None:
            date = dt_util.as_local(dt_util.now()).strftime("%Y%m%d")
        day_dir = os.path.join(self.base_dir, "frames", date)
        if not await self.hass.async_add_executor_job(_has_frames, day_dir):
            _LOGGER.warning("time-lapse: no frames to compile for %s", date)
            return None
        out = os.path.join(self.base_dir, f"timelapse-{date}.mp4")
        await self.hass.async_add_executor_job(os.makedirs, self.base_dir, True)
        cmd = [
            "ffmpeg", "-y", "-hide_banner", "-loglevel", "error",
            "-framerate", str(self.fps),
            "-pattern_type", "glob", "-i", os.path.join(day_dir, "*.jpg"),
            "-c:v", "libx264", "-pix_fmt", "yuv420p", "-movflags", "+faststart",
            out,
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            _LOGGER.error("time-lapse compile failed: %s", stderr.decode(errors="replace")[:300])
            return None
        _LOGGER.info("time-lapse compiled: %s", out)
        if not self.keep_frames:
            await self.hass.async_add_executor_job(_rmtree, day_dir)
        return out


def _write_file(day_dir: str, path: str, data: bytes) -> None:
    os.makedirs(day_dir, exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)


def _has_frames(day_dir: str) -> bool:
    return os.path.isdir(day_dir) and any(
        n.endswith(".jpg") for n in os.listdir(day_dir)
    )


def _rmtree(path: str) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)
