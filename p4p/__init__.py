"""p4p — a local client for the UBIA/TUTK P4P protocol (RBX-S73 camera).

This package is the runtime protocol library that the local bridge daemon (and,
later, a Home Assistant integration) build on. It is intentionally free of any
dependency on the analysis tooling in ``scripts/`` so it can be packaged and run
standalone (e.g. in Docker on the camera's VLAN).

Layers:
  * :mod:`p4p.crypto`     — the fixed packet obfuscation (reversed from the SDK)
  * :mod:`p4p.packet`     — P4P framing (16-byte header + msgtype)
  * :mod:`p4p.lansearch`  — LAN discovery (UDP 32762) + LanSearchInfo parsing
  * :mod:`p4p.session`    — direct LAN session (preconnect/PUNCH2LAN + KCP) [WIP]

See docs/session-flow.md for the reverse-engineered protocol this implements.
"""

from __future__ import annotations

__version__ = "0.0.1"
