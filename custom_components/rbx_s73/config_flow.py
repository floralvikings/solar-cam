"""Config flow for the RBX-S73 camera (UI setup)."""

from __future__ import annotations

import socket
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.helpers.selector import TextSelector

from .const import CONF_CLIENT_IP, CONF_HOST, CONF_UID, DOMAIN
from .p4p.lansearch import discover


def _local_ip_towards(host: str) -> str:
    """Best-effort local IP on the route to the camera (default client_ip)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, 32762))
        return s.getsockname()[0]
    except OSError:
        return ""
    finally:
        s.close()


def _validate(host: str, uid: str, client_ip: str):
    """Blocking: LAN-search the camera to confirm it's reachable. Returns info."""
    bcast = client_ip.rsplit(".", 1)[0] + ".255" if client_ip else "255.255.255.255"
    results = discover(uid, targets=[bcast, host], timeout=12.0)
    for info in results:
        if info.source_ip == host or info.uid.upper() == uid.upper():
            return info
    return None


class RbxS73ConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for RBX-S73."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            host = user_input[CONF_HOST].strip()
            uid = user_input[CONF_UID].strip().upper()
            client_ip = user_input.get(CONF_CLIENT_IP) or await self.hass.async_add_executor_job(
                _local_ip_towards, host
            )
            await self.async_set_unique_id(uid)
            self._abort_if_unique_id_configured()
            info = await self.hass.async_add_executor_job(_validate, host, uid, client_ip)
            if info is None:
                errors["base"] = "cannot_connect"
            else:
                return self.async_create_entry(
                    title=f"RBX-S73 {host}",
                    data={CONF_HOST: host, CONF_UID: uid, CONF_CLIENT_IP: client_ip},
                )

        schema = vol.Schema(
            {
                vol.Required(CONF_HOST): TextSelector(),
                vol.Required(CONF_UID): TextSelector(),
                vol.Optional(CONF_CLIENT_IP, default=""): TextSelector(),
            }
        )
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)
