"""PTZ control buttons for the RBX-S73 (pan/tilt over the live session).

The camera serves one AV session, so PTZ rides the active video session via a
Unix control socket into the capture subprocess (see coordinator.async_send_control).
Each direction press is a short "nudge" (move, then auto-stop); a Stop button
halts immediately.
"""

from __future__ import annotations

import asyncio

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, PTZ_DIRECTIONS, PTZ_NUDGE_SECONDS
from .coordinator import RbxS73Device


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the PTZ buttons."""
    device: RbxS73Device = hass.data[DOMAIN][entry.entry_id]
    entities: list[ButtonEntity] = [
        RbxS73PtzButton(device, direction, icon)
        for direction, icon in PTZ_DIRECTIONS.items()
    ]
    entities.append(RbxS73PtzStopButton(device))
    async_add_entities(entities)


class _PtzBase(ButtonEntity):
    _attr_has_entity_name = True

    def __init__(self, device: RbxS73Device) -> None:
        self._device = device
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device.uid)},
            name=f"RBX-S73 {device.host}",
            manufacturer="SEHMUA",
            model="RBX-S73",
        )


class RbxS73PtzButton(_PtzBase):
    """A single pan/tilt direction; a press nudges then auto-stops."""

    def __init__(self, device: RbxS73Device, direction: str, icon: str) -> None:
        super().__init__(device)
        self._direction = direction
        self._attr_name = f"Pan {direction}"
        self._attr_icon = icon
        self._attr_unique_id = f"{device.uid}_ptz_{direction}"

    async def async_press(self) -> None:
        await self._device.async_send_control(f"ptz {self._direction}")
        await asyncio.sleep(PTZ_NUDGE_SECONDS)
        await self._device.async_send_control("ptz stop")


class RbxS73PtzStopButton(_PtzBase):
    """Halt pan/tilt immediately."""

    def __init__(self, device: RbxS73Device) -> None:
        super().__init__(device)
        self._attr_name = "Pan stop"
        self._attr_icon = "mdi:stop"
        self._attr_unique_id = f"{device.uid}_ptz_stop"

    async def async_press(self) -> None:
        await self._device.async_send_control("ptz stop")
