#!/usr/bin/env bash
# Copy the canonical p4p library into the HACS integration (keep them identical).
set -e
cd "$(dirname "$0")/.."
cp p4p/__init__.py p4p/crypto.py p4p/packet.py p4p/lansearch.py p4p/session.py \
   p4p/kcp.py p4p/client.py custom_components/rbx_s73/p4p/
echo "synced p4p -> custom_components/rbx_s73/p4p"
