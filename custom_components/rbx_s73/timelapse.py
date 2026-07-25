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
import tempfile
from datetime import datetime, timedelta

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.event import (
    async_call_later,
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
    EXPORT_TTL_HOURS,
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
        await self.hass.async_add_executor_job(_ensure_dir, self.base_dir)
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

    # ---- on-demand range export --------------------------------------
    async def async_export(self, start, end) -> str | None:
        """Compile frames in [start, end] into a temp mp4 (auto-deleted).

        Returns the output path (under <base>/exports/), or None if the range
        held no frames. The file is removed after EXPORT_TTL_HOURS.
        """
        s = _to_naive_local(start)
        e = _to_naive_local(end)
        if e < s:
            s, e = e, s
        frames_root = os.path.join(self.base_dir, "frames")
        frames = await self.hass.async_add_executor_job(
            _collect_frames, frames_root, s, e
        )
        if not frames:
            _LOGGER.warning("time-lapse export: no frames between %s and %s", s, e)
            return None

        exports_dir = os.path.join(self.base_dir, "exports")
        name = f"export-{s:%Y%m%d-%H%M}-{e:%Y%m%d-%H%M}.mp4"
        out = os.path.join(exports_dir, name)
        tmp = await self.hass.async_add_executor_job(_stage_symlinks, frames)
        try:
            await self.hass.async_add_executor_job(_ensure_dir, exports_dir)
            await self.hass.async_add_executor_job(_sweep_old, exports_dir)
            cmd = [
                "ffmpeg", "-y", "-hide_banner", "-loglevel", "error",
                "-framerate", str(self.fps),
                "-start_number", "0", "-i", os.path.join(tmp, "%06d.jpg"),
                "-c:v", "libx264", "-pix_fmt", "yuv420p", "-movflags", "+faststart",
                out,
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE
            )
            _, stderr = await proc.communicate()
            if proc.returncode != 0:
                _LOGGER.error("export compile failed: %s", stderr.decode(errors="replace")[:300])
                return None
        finally:
            await self.hass.async_add_executor_job(_rmtree, tmp)

        _LOGGER.info("time-lapse export ready (%d frames): %s", len(frames), out)
        async_call_later(
            self.hass, EXPORT_TTL_HOURS * 3600, _delete_later(self.hass, out)
        )
        return out


@callback
def _delete_later(hass: HomeAssistant, path: str):
    async def _cb(_now):
        await hass.async_add_executor_job(_unlink, path)
        _LOGGER.debug("expired export removed: %s", path)
    return _cb


def _to_naive_local(dtobj: datetime) -> datetime:
    if dtobj.tzinfo is not None:
        dtobj = dt_util.as_local(dtobj).replace(tzinfo=None)
    return dtobj


def _collect_frames(frames_root: str, start: datetime, end: datetime) -> list[str]:
    if not os.path.isdir(frames_root):
        return []
    picked: list[tuple[datetime, str]] = []
    for day in os.listdir(frames_root):
        day_dir = os.path.join(frames_root, day)
        if not os.path.isdir(day_dir):
            continue
        for fn in os.listdir(day_dir):
            if not fn.endswith(".jpg"):
                continue
            try:
                ts = datetime.strptime(day + fn[:-4], "%Y%m%d%H%M%S")
            except ValueError:
                continue
            if start <= ts <= end:
                picked.append((ts, os.path.join(day_dir, fn)))
    picked.sort()
    return [p for _, p in picked]


def _stage_symlinks(frames: list[str]) -> str:
    tmp = tempfile.mkdtemp(prefix="rbx_tl_")
    for i, src in enumerate(frames):
        os.symlink(src, os.path.join(tmp, f"{i:06d}.jpg"))
    return tmp


def _sweep_old(exports_dir: str) -> None:
    """Remove exports older than the TTL (belt-and-suspenders vs. the timer)."""
    import time

    cutoff = time.time() - EXPORT_TTL_HOURS * 3600
    if not os.path.isdir(exports_dir):
        return
    for fn in os.listdir(exports_dir):
        path = os.path.join(exports_dir, fn)
        try:
            if os.path.isfile(path) and os.path.getmtime(path) < cutoff:
                os.unlink(path)
        except OSError:
            pass


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _unlink(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


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
