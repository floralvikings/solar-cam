"""SEHMUA RBX-S73 local camera integration (cloud-free, LAN P4P).

The camera's proprietary P4P/H.264 stream is captured by a vendored pure-Python
client and transcoded to MJPEG by ffmpeg on the HA host, then served natively
by Home Assistant. No cloud, no go2rtc dependency. Includes a time-lapse switch.
"""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .coordinator import RbxS73Device
from .timelapse import TimelapseManager

PLATFORMS: list[Platform] = [Platform.CAMERA, Platform.SWITCH]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up RBX-S73 from a config entry."""
    device = RbxS73Device(hass, entry)
    device.timelapse = TimelapseManager(hass, device, entry)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = device
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    await device.async_apply_session_mode()  # permanent/keep-warm/solar/on-demand
    entry.async_on_unload(entry.add_update_listener(_async_options_updated))
    return True


async def _async_options_updated(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Re-apply time-lapse schedule + session model when options change."""
    device: RbxS73Device | None = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    if device:
        if device.timelapse:
            await device.timelapse.async_reschedule()
        await device.async_apply_session_mode()


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        device: RbxS73Device = hass.data[DOMAIN].pop(entry.entry_id, None)
        if device:
            if device.timelapse:
                await device.timelapse.async_stop()
            await device.async_stop()
    return unloaded
