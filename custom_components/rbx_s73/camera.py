"""Camera entity for the RBX-S73. Local MJPEG (H.264->ffmpeg->MJPEG); no cloud."""

from __future__ import annotations

from aiohttp import web

from homeassistant.components.camera import Camera
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import RbxS73Device


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the camera entity from a config entry."""
    device: RbxS73Device = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([RbxS73Camera(device)])


class RbxS73Camera(Camera):
    """A SEHMUA RBX-S73 camera served locally as MJPEG."""

    _attr_has_entity_name = True
    _attr_name = None
    # No STREAM feature: HA serves the camera via MJPEG (handle_async_mjpeg_stream)
    # and stills (async_camera_image), both backed by the shared pipeline.

    def __init__(self, device: RbxS73Device) -> None:
        super().__init__()
        self._device = device
        self._attr_unique_id = device.uid
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device.uid)},
            name=f"RBX-S73 {device.host}",
            manufacturer="SEHMUA",
            model="RBX-S73",
        )

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        """Return a single JPEG frame (shared with the live stream)."""
        return await self._device.stream.snapshot()

    async def handle_async_mjpeg_stream(
        self, request: web.Request
    ) -> web.StreamResponse:
        """Serve the live MJPEG stream."""
        return await self._device.stream.mjpeg_response(request)
