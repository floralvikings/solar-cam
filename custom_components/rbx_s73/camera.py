"""Camera entity for the RBX-S73. Streams via go2rtc; no cloud."""

from __future__ import annotations

from homeassistant.components.camera import Camera, CameraEntityFeature
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
    """A SEHMUA RBX-S73 camera served locally via go2rtc."""

    _attr_has_entity_name = True
    _attr_name = None
    _attr_supported_features = CameraEntityFeature.STREAM

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

    async def stream_source(self) -> str | None:
        """Return the go2rtc source; HA restreams it (WebRTC/HLS) + snapshots."""
        return self._device.go2rtc_source()
