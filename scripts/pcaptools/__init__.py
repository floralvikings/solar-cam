"""pcaptools: read-only PCAP analysis helpers for the RBX-S73 project.

The package is split so that all *analysis* logic operates on plain
``PacketRow`` objects and is therefore unit-testable without tshark or a
real capture. Only :mod:`pcaptools.tshark` shells out to ``tshark``.
"""

from __future__ import annotations

from .model import (
    Conversation,
    Endpoint,
    PacketRow,
    Summary,
)

__all__ = [
    "PacketRow",
    "Endpoint",
    "Conversation",
    "Summary",
]

__version__ = "0.1.0"
