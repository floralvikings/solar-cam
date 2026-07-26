"""Single-session MJPEG fan-out for one RBX-S73 camera.

The camera serves only ONE AV session at a time, so every Home Assistant
consumer (live MJPEG viewers *and* snapshots) shares a single
``capture.py -> ffmpeg`` pipeline. Frames are parsed from ffmpeg's ``mpjpeg``
output; the latest frame is kept for snapshots and pushed to all live viewers.

The pipeline starts on the first consumer and stops a few seconds after the
last one disconnects, so the (battery/solar) camera only streams while
something is actually watching.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal

from aiohttp import web

_LOGGER = logging.getLogger(__name__)

_BOUNDARY = "rbxframe"
_IDLE_STOP = 8.0  # stop the pipeline this long after the last consumer leaves
_FIRST_FRAME_TIMEOUT = 25.0  # camera wake + P4P handshake + first keyframe
_STREAM_IDLE_TIMEOUT = 30.0  # drop a viewer if no new frame for this long
# The camera serves one session and wedges under rapid open/close churn, so we
# space sessions out and serve still-image polls (dashboard thumbnails) from a
# cache instead of waking the camera each time.
_SESSION_COOLDOWN = 15.0  # min gap between a stop and the next session start
_SNAPSHOT_CACHE_TTL = 300.0  # reuse the last frame for stills up to this old
_KEEPWARM_IDLE = 300.0  # keep-warm: hold the session this long after last use


class CameraStream:
    """Owns the shared capture->ffmpeg->mjpeg pipeline for one camera."""

    def __init__(self, cmd_factory) -> None:
        # cmd_factory() -> a shell command string producing mpjpeg on stdout.
        self._cmd_factory = cmd_factory
        self._proc: asyncio.subprocess.Process | None = None
        self._reader_task: asyncio.Task | None = None
        self._latest: bytes | None = None
        self._new_frame = asyncio.Event()
        self._refs = 0
        self._start_lock = asyncio.Lock()
        self._stop_handle: asyncio.TimerHandle | None = None
        # still-image cache (persists across pipeline stops)
        self._cache_jpeg: bytes | None = None
        self._cache_ts = 0.0
        self._last_stop = 0.0  # loop time of the last stop (for cooldown)
        # session model: permanent = never idle-stop; keep-warm = long idle hold
        self._permanent = False
        self._idle_hold = _IDLE_STOP
        self._perm_task: asyncio.Task | None = None

    # ---- pipeline lifecycle ------------------------------------------
    async def _ensure_running(self) -> None:
        async with self._start_lock:
            if self._proc is not None and self._proc.returncode is None:
                return
            # Cooldown: the camera wedges if a new session opens too soon after
            # the previous one closes. Wait out the remaining gap.
            gap = _SESSION_COOLDOWN - (asyncio.get_running_loop().time() - self._last_stop)
            if gap > 0:
                _LOGGER.debug("session cooldown: waiting %.1fs", gap)
                await asyncio.sleep(gap)
            cmd = self._cmd_factory()
            _LOGGER.debug("starting mjpeg pipeline")
            self._latest = None
            # start_new_session=True puts sh + capture.py + ffmpeg in their own
            # process group so stop() can kill the WHOLE group. Otherwise killing
            # sh orphans capture.py, which keeps holding the camera's one session.
            self._proc = await asyncio.create_subprocess_exec(
                "sh",
                "-c",
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                start_new_session=True,
            )
            self._reader_task = asyncio.create_task(self._read_frames(self._proc))

    async def _read_frames(self, proc: asyncio.subprocess.Process) -> None:
        """Parse ffmpeg's mpjpeg stream: --boundary / headers / N JPEG bytes."""
        stdout = proc.stdout
        assert stdout is not None
        try:
            while True:
                line = await stdout.readline()
                if not line:
                    break
                if not line.startswith(b"--"):
                    continue
                clen: int | None = None
                while True:
                    header = await stdout.readline()
                    if not header or header in (b"\r\n", b"\n"):
                        break
                    if b":" in header:
                        key, val = header.split(b":", 1)
                        if key.strip().lower() == b"content-length":
                            try:
                                clen = int(val.strip())
                            except ValueError:
                                clen = None
                if not clen:
                    continue
                try:
                    jpeg = await stdout.readexactly(clen)
                except asyncio.IncompleteReadError:
                    break
                self._latest = jpeg
                self._cache_jpeg = jpeg
                self._cache_ts = asyncio.get_running_loop().time()
                self._new_frame.set()
                self._new_frame.clear()
        except asyncio.CancelledError:
            raise
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("mjpeg reader stopped: %s", err)
        finally:
            if self._proc is proc:
                self._proc = None
                self._latest = None

    def _schedule_stop(self) -> None:
        self._cancel_stop()
        loop = asyncio.get_running_loop()
        self._stop_handle = loop.call_later(
            self._idle_hold, lambda: loop.create_task(self._stop_if_idle())
        )

    def _cancel_stop(self) -> None:
        if self._stop_handle is not None:
            self._stop_handle.cancel()
            self._stop_handle = None

    async def _stop_if_idle(self) -> None:
        if self._refs <= 0 and not self._permanent:
            await self.stop()

    async def stop(self) -> None:
        self._cancel_stop()
        proc, self._proc = self._proc, None
        task, self._reader_task = self._reader_task, None
        if task is not None:
            task.cancel()
        if proc is not None and proc.returncode is None:
            _kill_group(proc)
            try:
                await proc.wait()
            except ProcessLookupError:
                pass
        self._latest = None
        self._last_stop = asyncio.get_running_loop().time()

    async def _acquire(self) -> None:
        self._cancel_stop()
        self._refs += 1
        await self._ensure_running()

    def _release(self) -> None:
        self._refs = max(0, self._refs - 1)
        if self._refs == 0 and not self._permanent:
            self._schedule_stop()

    async def acquire(self) -> None:
        """Public: hold the session up (e.g. for PTZ). Pair with release()."""
        await self._acquire()

    def release(self) -> None:
        """Public: drop a hold taken with acquire()."""
        self._release()

    # ---- session model (permanent / keep-warm) -----------------------
    def set_idle_hold(self, seconds: float) -> None:
        """How long to keep the session up after the last consumer leaves."""
        self._idle_hold = seconds

    async def set_permanent(self, on: bool) -> None:
        """Permanent = keep one session alive 24/7 (auto-reconnect on drop)."""
        if on and not self._permanent:
            self._permanent = True
            self._cancel_stop()
            self._perm_task = asyncio.create_task(self._supervise())
        elif not on and self._permanent:
            self._permanent = False
            if self._perm_task:
                self._perm_task.cancel()
                self._perm_task = None
            # hand off to keep-warm idle-stop if nobody else is watching
            if self._refs <= 0:
                self._schedule_stop()

    async def _supervise(self) -> None:
        """Keep the pipeline alive while permanent; reconnect if it dies."""
        try:
            while self._permanent:
                await self._ensure_running()  # (re)start, honoring cooldown
                proc = self._proc
                if proc is not None:
                    await proc.wait()  # block until the camera/session drops
                if self._permanent:
                    _LOGGER.debug("permanent session dropped; reconnecting")
        except asyncio.CancelledError:
            pass

    # ---- consumers ----------------------------------------------------
    async def snapshot(self, max_age: float = _SNAPSHOT_CACHE_TTL) -> bytes | None:
        """Return a recent JPEG frame.

        Serves the cached frame if it's younger than ``max_age`` (so HA's
        frequent dashboard-thumbnail polls don't wake the camera every time).
        Pass ``max_age=0`` to force a fresh capture (time-lapse uses a small
        value). Falls back to the cache if a fresh capture times out.
        """
        loop = asyncio.get_running_loop()
        if (
            self._cache_jpeg is not None
            and (loop.time() - self._cache_ts) <= max_age
        ):
            return self._cache_jpeg
        await self._acquire()
        try:
            if self._latest is None:
                try:
                    await asyncio.wait_for(
                        self._new_frame.wait(), _FIRST_FRAME_TIMEOUT
                    )
                except asyncio.TimeoutError:
                    return self._cache_jpeg
            return self._latest or self._cache_jpeg
        finally:
            self._release()

    async def mjpeg_response(self, request: web.Request) -> web.StreamResponse:
        """Serve a multipart/x-mixed-replace MJPEG stream to one viewer."""
        await self._acquire()
        response = web.StreamResponse(
            status=200,
            headers={
                "Content-Type": f"multipart/x-mixed-replace; boundary={_BOUNDARY}",
                "Cache-Control": "no-cache",
            },
        )
        try:
            await response.prepare(request)
            if self._latest is not None:
                await _write_frame(response, self._latest)
            timeout = _FIRST_FRAME_TIMEOUT
            while True:
                try:
                    await asyncio.wait_for(self._new_frame.wait(), timeout)
                except asyncio.TimeoutError:
                    break
                timeout = _STREAM_IDLE_TIMEOUT
                frame = self._latest
                if frame is not None:
                    await _write_frame(response, frame)
        except (ConnectionResetError, ConnectionError, asyncio.CancelledError):
            pass
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("mjpeg viewer ended: %s", err)
        finally:
            self._release()
        return response

def _kill_group(proc: asyncio.subprocess.Process) -> None:
    """Kill the whole process group (sh + capture.py + ffmpeg), not just sh."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            proc.kill()
        except ProcessLookupError:
            pass


async def _write_frame(response: web.StreamResponse, frame: bytes) -> None:
    await response.write(
        b"--"
        + _BOUNDARY.encode()
        + b"\r\nContent-Type: image/jpeg\r\nContent-Length: "
        + str(len(frame)).encode()
        + b"\r\n\r\n"
        + frame
        + b"\r\n"
    )
