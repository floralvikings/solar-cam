"""SEHMUA RBX-S73 local camera integration (cloud-free, LAN P4P).

The camera's proprietary P4P/H.264 stream is captured by a vendored pure-Python
client and transcoded to MJPEG by ffmpeg on the HA host, then served natively
by Home Assistant. No cloud, no go2rtc dependency.
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
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = RbxS73Device(hass, entry)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        device: RbxS73Device = hass.data[DOMAIN].pop(entry.entry_id, None)
        if device:
            await device.async_stop()
    return unloaded
