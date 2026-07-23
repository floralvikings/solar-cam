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

from aiohttp import web

_LOGGER = logging.getLogger(__name__)

_BOUNDARY = "rbxframe"
_IDLE_STOP = 8.0  # stop the pipeline this long after the last consumer leaves
_FIRST_FRAME_TIMEOUT = 25.0  # camera wake + P4P handshake + first keyframe
_STREAM_IDLE_TIMEOUT = 30.0  # drop a viewer if no new frame for this long


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

    # ---- pipeline lifecycle ------------------------------------------
    async def _ensure_running(self) -> None:
        async with self._start_lock:
            if self._proc is not None and self._proc.returncode is None:
                return
            cmd = self._cmd_factory()
            _LOGGER.debug("starting mjpeg pipeline")
            self._latest = None
            self._proc = await asyncio.create_subprocess_exec(
                "sh",
                "-c",
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
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
            _IDLE_STOP, lambda: loop.create_task(self._stop_if_idle())
        )

    def _cancel_stop(self) -> None:
        if self._stop_handle is not None:
            self._stop_handle.cancel()
            self._stop_handle = None

    async def _stop_if_idle(self) -> None:
        if self._refs <= 0:
            await self.stop()

    async def stop(self) -> None:
        self._cancel_stop()
        proc, self._proc = self._proc, None
        task, self._reader_task = self._reader_task, None
        if task is not None:
            task.cancel()
        if proc is not None and proc.returncode is None:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
        self._latest = None

    async def _acquire(self) -> None:
        self._cancel_stop()
        self._refs += 1
        await self._ensure_running()

    def _release(self) -> None:
        self._refs = max(0, self._refs - 1)
        if self._refs == 0:
            self._schedule_stop()

    # ---- consumers ----------------------------------------------------
    async def snapshot(self) -> bytes | None:
        """Return the most recent JPEG frame (starts the pipeline if idle)."""
        await self._acquire()
        try:
            if self._latest is None:
                try:
                    await asyncio.wait_for(
                        self._new_frame.wait(), _FIRST_FRAME_TIMEOUT
                    )
                except asyncio.TimeoutError:
                    return None
            return self._latest
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
                await self._write_frame(response, self._latest)
            timeout = _FIRST_FRAME_TIMEOUT
            while True:
                try:
                    await asyncio.wait_for(self._new_frame.wait(), timeout)
                except asyncio.TimeoutError:
                    break
                timeout = _STREAM_IDLE_TIMEOUT
                frame = self._latest
                if frame is not None:
                    await self._write_frame(response, frame)
        except (ConnectionResetError, ConnectionError, asyncio.CancelledError):
            pass
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("mjpeg viewer ended: %s", err)
        finally:
            self._release()
        return response

    @staticmethod
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
