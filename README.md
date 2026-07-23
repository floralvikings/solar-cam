# RBX-S73 Local Camera Research

Reverse-engineering the **SEHMUA RBX-S73** solar Wi-Fi pan/tilt camera (UBox
app) so it can run **locally in Home Assistant** without the vendor cloud.

See [`CLAUDE.md`](CLAUDE.md) for the full objective, method, and safety rules.
This README covers how to *use* the tooling in this repo.

## Status

**Phase 1 — read-only analysis tooling (this commit).** No captures taken yet.
A prior TCP scan found no listening services on the camera (see
[`docs/network-behavior.md`](docs/network-behavior.md)); the working hypothesis
is a cloud-assisted P2P protocol over UDP. Nothing is confirmed until we have
captures. Running findings live in
[`docs/research-log.md`](docs/research-log.md).

## Setup

Tools shell out to **tshark** (Wireshark CLI) and otherwise use only the Python
standard library. Analyzing an existing capture never needs root.

```bash
# tshark (Wireshark CLI)
brew install wireshark            # macOS
sudo apt install tshark           # Debian/Ubuntu

# Python env (only pytest is needed, for the test suite)
python3 -m venv .venv
.venv/bin/pip install pytest
```

If `tshark` is not on `PATH`, pass `--tshark /path/to/tshark` to any tool.

## Tools (`scripts/`)

All are **read-only** except `probe_camera.py`, which is a non-destructive
active probe. All accept `--json` for machine-readable output.

| Tool | Purpose |
|------|---------|
| `summarize_pcap.py` | One capture → protocols, endpoints, ports, DNS/SNI, flows, size histogram, keepalive + high-bandwidth (video) flow detection |
| `compare_sessions.py` | Diff captures (idle vs live/pan/tilt/wan-blocked) → flows & DNS names unique to each scenario |
| `extract_dns.py` | Every DNS query + answer (maps cloud dependencies) |
| `udp_flow_report.py` | Fingerprint proprietary UDP flows: payload lengths, header bytes, entropy, sequence-counter fields |
| `probe_camera.py` | Liveness + targeted TCP/RTSP/ONVIF-WS-Discovery/SSDP probe (non-destructive) |

### Examples

```bash
# Summarize one capture (camera IP recommended; otherwise guessed)
python scripts/summarize_pcap.py captures/live-view.pcap --camera-ip 192.168.50.42

# Compare scenarios — LABEL=PATH; isolates what each action adds
python scripts/compare_sessions.py \
    idle=captures/idle.pcap \
    live=captures/live-view.pcap \
    pan=captures/pan.pcap \
    wanblock=captures/wan-blocked.pcap \
    --camera-ip 192.168.50.42

# What does the camera resolve?
python scripts/extract_dns.py captures/boot.pcap --camera-ip 192.168.50.42

# Fingerprint the proprietary UDP video/control flows
python scripts/udp_flow_report.py captures/live-view.pcap

# Is the camera awake / does it expose anything locally? (active, safe)
python scripts/probe_camera.py 192.168.50.42
```

## Capturing traffic

Full step-by-step (MikroTik / Dell SPAN / macOS, and where to tap) is in
[`docs/capture-procedure.md`](docs/capture-procedure.md) — **no Linux VM
needed**. Label each scenario clearly (boot, idle, app-startup, live-view, pan,
tilt, audio, motion, sd-playback, wan-blocked). **Wake the camera first** — it
may sleep its radio when idle.

```bash
sudo tcpdump -i <iface> host 192.168.88.113 -w captures/rbx-s73-idle.pcap
```

Captures live in `captures/` and are **git-ignored** — they can contain device
UIDs, tokens, and MACs. See [`CLAUDE.md`](CLAUDE.md) → Security Requirements.

## Tests

```bash
.venv/bin/python -m pytest tests/ -v
```

The analysis logic is unit-tested on hand-built packet rows (no tshark needed);
one integration test builds a tiny pcap and runs real tshark end-to-end.

## Layout

```
scripts/           analysis CLIs + the pcaptools package (shared logic)
  pcaptools/       tshark wrapper + pure, testable analysis modules
tests/             pytest suite
docs/              device / network / protocol / cloud / firmware / hardware notes + research log
wireshark/         display-filter cheatsheet
integrations/      go2rtc / home-assistant / frigate config (added once local access works)
captures/          pcaps (git-ignored)
firmware/          firmware images (git-ignored)
```
