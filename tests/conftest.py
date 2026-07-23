"""Make the pcaptools (scripts/) and p4p (repo root) packages importable."""

from __future__ import annotations

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(__file__))
_SCRIPTS = os.path.join(_ROOT, "scripts")
for _p in (_SCRIPTS, _ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
