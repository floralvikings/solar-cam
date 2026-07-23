"""SEHMUA RBX-S73 local camera integration (cloud-free, LAN P4P).

go2rtc (bundled in Home Assistant) owns the single AV session by exec'ing the
vendored capture.py; this integration provides the camera entity and the
go2rtc source string.
"""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .coordinator import RbxS73Device

PLATFORMS: list[Platform] = [Platform.CAMERA]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up RBX-S73 from a config entry."""
    device = RbxS73Device(hass, entry)
    await device.async_setup()  # register the go2rtc stream, resolve RTSP URL
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = device
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        device: RbxS73Device = hass.data[DOMAIN].pop(entry.entry_id, None)
        if device:
            await device.async_teardown()
    return unloaded
