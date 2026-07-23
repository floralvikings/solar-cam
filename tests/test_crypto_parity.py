"""Guarantee the daemon's p4p.crypto never diverges from the analysis copy."""

from __future__ import annotations

import os

from p4p import crypto as p4p_crypto
from pcaptools import ubia_crypto


def test_same_key():
    assert p4p_crypto.KEY == ubia_crypto.KEY


def test_encode_decode_identical_random():
    for n in (0, 1, 15, 16, 17, 40, 408, 1000):
        data = os.urandom(n)
        assert p4p_crypto.encode(data) == ubia_crypto.encode(data)
        assert p4p_crypto.decode(data) == ubia_crypto.decode(data)
