"""Constants for the RBX-S73 camera integration."""

from __future__ import annotations

DOMAIN = "rbx_s73"

CONF_HOST = "host"          # camera IP
CONF_UID = "uid"            # 20-char device UID
CONF_CLIENT_IP = "client_ip"  # this HA host's LAN IP (video destination)

# The camera only serves one AV session at a time; the integration owns it.
LAN_SEARCH_PORT = 32762
