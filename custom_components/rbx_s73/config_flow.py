"""Config flow for the RBX-S73 camera (UI setup)."""

from __future__ import annotations

import socket
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.core import callback
from homeassistant.helpers.selector import (
    SelectSelector,
    SelectSelectorConfig,
    TextSelector,
)

from .const import (
    CONF_CLIENT_IP,
    CONF_HOST,
    CONF_SESSION_MODE,
    CONF_TL_COMPILE_HOUR,
    CONF_TL_DIR,
    CONF_TL_FPS,
    CONF_TL_KEEP_FRAMES,
    CONF_TL_RATE,
    CONF_TL_RATE_UNIT,
    CONF_UID,
    DEFAULT_SESSION_MODE,
    DEFAULT_TL_COMPILE_HOUR,
    DEFAULT_TL_DIR,
    DEFAULT_TL_FPS,
    DEFAULT_TL_KEEP_FRAMES,
    DEFAULT_TL_RATE,
    DEFAULT_TL_RATE_UNIT,
    DOMAIN,
    SESSION_MODES,
    TL_UNIT_SECONDS,
)
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

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> "RbxS73OptionsFlow":
        return RbxS73OptionsFlow()

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


class RbxS73OptionsFlow(OptionsFlow):
    """Time-lapse options."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        opts = self.config_entry.options
        schema = vol.Schema(
            {
                vol.Optional(
                    CONF_SESSION_MODE,
                    default=opts.get(CONF_SESSION_MODE, DEFAULT_SESSION_MODE),
                ): SelectSelector(
                    SelectSelectorConfig(
                        options=SESSION_MODES, translation_key="session_mode"
                    )
                ),
                vol.Optional(
                    CONF_TL_RATE, default=opts.get(CONF_TL_RATE, DEFAULT_TL_RATE)
                ): vol.All(vol.Coerce(int), vol.Range(min=1, max=600)),
                vol.Optional(
                    CONF_TL_RATE_UNIT,
                    default=opts.get(CONF_TL_RATE_UNIT, DEFAULT_TL_RATE_UNIT),
                ): SelectSelector(
                    SelectSelectorConfig(
                        options=list(TL_UNIT_SECONDS), translation_key="tl_rate_unit"
                    )
                ),
                vol.Optional(
                    CONF_TL_FPS, default=opts.get(CONF_TL_FPS, DEFAULT_TL_FPS)
                ): vol.All(vol.Coerce(int), vol.Range(min=1, max=60)),
                vol.Optional(
                    CONF_TL_COMPILE_HOUR,
                    default=opts.get(CONF_TL_COMPILE_HOUR, DEFAULT_TL_COMPILE_HOUR),
                ): vol.All(vol.Coerce(int), vol.Range(min=-1, max=23)),
                vol.Optional(
                    CONF_TL_KEEP_FRAMES,
                    default=opts.get(CONF_TL_KEEP_FRAMES, DEFAULT_TL_KEEP_FRAMES),
                ): bool,
                vol.Optional(
                    CONF_TL_DIR, default=opts.get(CONF_TL_DIR, DEFAULT_TL_DIR)
                ): TextSelector(),
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)
