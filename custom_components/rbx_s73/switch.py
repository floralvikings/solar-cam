"""Time-lapse enable/disable switch (+ compile service) for the RBX-S73."""

from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, SupportsResponse
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import (
    AddEntitiesCallback,
    async_get_current_platform,
)
from homeassistant.helpers.restore_state import RestoreEntity

from .const import DOMAIN
from .coordinator import RbxS73Device


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the time-lapse switch and register its compile service."""
    device: RbxS73Device = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([RbxS73TimelapseSwitch(device), RbxS73NightlightSwitch(device)])

    platform = async_get_current_platform()
    platform.async_register_entity_service(
        "compile_timelapse",
        {
            vol.Optional("start_date"): cv.date,
            vol.Optional("end_date"): cv.date,
            vol.Optional("date"): vol.Match(r"^\d{8}$"),  # legacy single-day
        },
        "async_compile_service",
        supports_response=SupportsResponse.OPTIONAL,
    )
    platform.async_register_entity_service(
        "export_timelapse",
        {vol.Required("start"): cv.datetime, vol.Required("end"): cv.datetime},
        "async_export_service",
        supports_response=SupportsResponse.OPTIONAL,
    )


class RbxS73TimelapseSwitch(SwitchEntity, RestoreEntity):
    """Turns scheduled time-lapse capture on/off (state survives restarts)."""

    _attr_has_entity_name = True
    _attr_name = "Time-lapse"
    _attr_icon = "mdi:timelapse"

    def __init__(self, device: RbxS73Device) -> None:
        self._device = device
        self._manager = device.timelapse
        self._attr_unique_id = f"{device.uid}_timelapse"
        self._attr_is_on = False
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device.uid)},
            name=f"RBX-S73 {device.host}",
            manufacturer="SEHMUA",
            model="RBX-S73",
        )

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        last = await self.async_get_last_state()
        if last is not None and last.state == "on":
            self._attr_is_on = True
            await self._manager.async_start()

    async def async_turn_on(self, **kwargs: Any) -> None:
        self._attr_is_on = True
        await self._manager.async_start()
        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs: Any) -> None:
        self._attr_is_on = False
        await self._manager.async_stop()
        self.async_write_ha_state()

    async def async_compile_service(
        self, start_date=None, end_date=None, date: str | None = None
    ) -> dict:
        """Entity service: compile a day or a range of days into an mp4."""
        sd = start_date.strftime("%Y%m%d") if start_date else date
        ed = end_date.strftime("%Y%m%d") if end_date else sd
        path = await self._manager.async_compile(sd, ed)
        if not path:
            return {"compiled": False, "reason": "no frames in that range"}
        rel = path.split("/media/", 1)[-1] if "/media/" in path else path
        return {
            "compiled": True,
            "path": path,
            "media_source": f"media-source://media_source/local/{rel}",
        }

    async def async_export_service(self, start, end) -> dict:
        """Entity service: export frames in a time range to a temp mp4.

        Returns the on-disk path and the Media-browser location; the file is
        auto-deleted after a few hours.
        """
        path = await self._manager.async_export(start, end)
        if not path:
            return {"exported": False, "reason": "no frames captured in that range"}
        rel = path.split("/media/", 1)[-1] if "/media/" in path else path
        return {
            "exported": True,
            "path": path,
            "media_source": f"media-source://media_source/local/{rel}",
        }


class RbxS73NightlightSwitch(SwitchEntity):
    """The camera's night light (ioType 46, SET_NIGHTLIGHT).

    Assumed state: the command is fire-and-forget. Our local session can send
    ioctrl but the camera does not route responses back to it yet, so we cannot
    read the real lamp state — HA shows what we last commanded.
    """

    _attr_has_entity_name = True
    _attr_name = "Night light"
    _attr_icon = "mdi:lightbulb-night"
    _attr_assumed_state = True

    def __init__(self, device: RbxS73Device) -> None:
        self._device = device
        self._attr_unique_id = f"{device.uid}_nightlight"
        self._attr_is_on = False
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device.uid)},
            name=f"RBX-S73 {device.host}",
            manufacturer="SEHMUA",
            model="RBX-S73",
        )

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self._device.async_send_control("light on")
        self._attr_is_on = True
        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._device.async_send_control("light off")
        self._attr_is_on = False
        self.async_write_ha_state()
