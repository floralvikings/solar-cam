"""Runs the pure-Python p4p client in a background thread and buffers frames.

The camera only serves one AV session at a time, so this coordinator owns the
single session and fans frames out to the camera entity. Streaming *delivery*
into HA (go2rtc / ffmpeg) is layered on top in camera.py.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import CONF_CLIENT_IP, CONF_HOST, CONF_UID
from .p4p.client import stream_h264

_LOGGER = logging.getLogger(__name__)


class RbxS73Coordinator:
    """Own the camera's LAN AV session and buffer H.264 frames."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.host: str = entry.data[CONF_HOST]
        self.uid: str = entry.data[CONF_UID]
        self.client_ip: str = entry.data[CONF_CLIENT_IP]
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        # latest complete keyframe (SPS+PPS+IDR) for snapshots
        self._keyframe: bytes = b""
        # per-frame subscribers (used by the live-stream delivery)
        self._subscribers: list[Callable[[bytes], None]] = []

    async def async_start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name=f"rbx_s73:{self.host}", daemon=True
        )
        self._thread.start()

    async def async_stop(self) -> None:
        self._stop.set()
        if self._thread:
            await self.hass.async_add_executor_job(self._thread.join, 5)

    def subscribe(self, cb: Callable[[bytes], None]) -> Callable[[], None]:
        """Register a per-frame callback; returns an unsubscribe function."""
        with self._lock:
            self._subscribers.append(cb)
        def _unsub() -> None:
            with self._lock:
                if cb in self._subscribers:
                    self._subscribers.remove(cb)
        return _unsub

    @property
    def latest_keyframe(self) -> bytes:
        with self._lock:
            return self._keyframe

    def _run(self) -> None:
        """Blocking loop: stream H.264, reconnecting on error."""
        cur = bytearray()   # accumulating GOP for keyframe snapshot
        while not self._stop.is_set():
            try:
                for frame in stream_h264(self.uid, self.host, self.client_ip):
                    if self._stop.is_set():
                        break
                    # snapshot bookkeeping: start a GOP at each SPS
                    if _has_nal(frame, 7):        # SPS -> new keyframe
                        cur = bytearray(frame)
                        with self._lock:
                            self._keyframe = bytes(cur)
                    # fan out to live subscribers
                    with self._lock:
                        subs = list(self._subscribers)
                    for cb in subs:
                        try:
                            cb(frame)
                        except Exception:  # a bad subscriber must not kill the loop
                            _LOGGER.debug("subscriber error", exc_info=True)
            except Exception as err:  # noqa: BLE001
                if not self._stop.is_set():
                    _LOGGER.warning("RBX-S73 %s stream error: %s; retrying", self.host, err)
                    time.sleep(3)


def _has_nal(frame: bytes, nal_type: int) -> bool:
    i = frame.find(b"\x00\x00\x00\x01")
    while i >= 0:
        if (frame[i + 4] & 0x1F) == nal_type:
            return True
        i = frame.find(b"\x00\x00\x00\x01", i + 4)
    return False
