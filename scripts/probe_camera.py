#!/usr/bin/env python3
"""Non-destructive liveness/service probe for the RBX-S73 camera.

What it does (and ONLY this):
  * ICMP ping + ARP-table check to tell whether the camera is awake.
  * Targeted TCP connect() attempts on a small curated list of camera/
    RTSP/ONVIF ports (NOT a full port scan -- nmap already covered that).
  * RTSP OPTIONS request on any open RTSP-ish port.
  * ONVIF WS-Discovery probe (multicast 239.255.255.250:3702).
  * SSDP M-SEARCH discovery (multicast 239.255.255.250:1900).

What it deliberately does NOT do: brute-force credentials, send malformed/
fuzzing packets, or scan hosts other than the target and standard
discovery multicast groups.

Wake the camera (open the app / trigger motion) immediately before running.

Examples:
    python scripts/probe_camera.py 192.168.50.42
    python scripts/probe_camera.py 192.168.50.42 --json
    python scripts/probe_camera.py 192.168.50.42 --no-discovery
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import socket
import subprocess
import sys
from typing import Any, Optional

# Curated, targeted set -- common camera/RTSP/ONVIF/HTTP/debug ports.
DEFAULT_TCP_PORTS = [
    80, 443, 554, 8554, 8000, 8080, 8081, 8443, 8888, 8899,
    88, 5000, 9000, 34567, 37777, 23, 22,
]
RTSP_PORTS = {554, 8554}

WS_DISCOVERY_ADDR = ("239.255.255.250", 3702)
SSDP_ADDR = ("239.255.255.250", 1900)

# --- UBIA/TUTK proprietary LAN discovery -----------------------------------
# Recovered by capturing the UBox app's startup broadcast (see
# docs/protocol-notes.md). The camera firmware implements the device side
# (p4p_device_handle_lansearchreq), so it answers this where it ignores
# SSDP/ONVIF/mDNS.
LAN_SEARCH_PORT = 32762
_LAN_SEARCH_PREFIX = bytes([0x07, 0x18, 0x10, 0x00])
_LAN_SEARCH_TYPE = bytes([0x01, 0x13])
_LAN_SEARCH_TAIL = bytes([0xFE, 0x3D, 0x03, 0x00, 0x00, 0x00, 0x00])
UID_LEN = 20


def build_lansearch_request(uid: str) -> bytes:
    """Build the 36-byte UBIA/TUTK LAN-search request for a device UID.

    Layout (little-endian length at offset 4):
        07 18 10 00 | <len:u16> | 01 13 | <uid:20 ascii> 00 | fe 3d 03 00*4
    """
    uid = uid.strip().upper()
    if len(uid) != UID_LEN or not uid.isalnum():
        raise ValueError(
            f"UID must be {UID_LEN} alphanumeric characters, got {uid!r}"
        )
    body = uid.encode("ascii") + b"\x00"
    total = len(_LAN_SEARCH_PREFIX) + 2 + len(_LAN_SEARCH_TYPE) + len(body) + len(
        _LAN_SEARCH_TAIL
    )
    return (
        _LAN_SEARCH_PREFIX
        + total.to_bytes(2, "little")
        + _LAN_SEARCH_TYPE
        + body
        + _LAN_SEARCH_TAIL
    )


def lan_search(
    uid: str,
    targets: list[str],
    timeout: float,
    port: int = LAN_SEARCH_PORT,
    max_replies: int = 10,
    bind_port: Optional[int] = LAN_SEARCH_PORT,
    repeat: int = 5,
    interval: float = 0.2,
) -> list[dict[str, Any]]:
    """Send the LAN-search request and collect replies.

    ``targets`` may mix broadcast and unicast addresses; one socket is reused
    so replies to any of them land here.

    We bind the local socket to ``bind_port`` (the same well-known port we
    send to) because the device may reply either to our source port *or* to
    the fixed discovery port -- binding it covers both. Falls back to an
    ephemeral port if the bind fails (e.g. port already in use).

    The real app broadcasts repeatedly rather than once, so ``repeat`` sends
    are made ``interval`` seconds apart before listening out the timeout.
    """
    payload = build_lansearch_request(uid)
    replies: list[dict[str, Any]] = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if bind_port is not None:
            try:
                s.bind(("", bind_port))
            except OSError:
                pass  # fall back to an ephemeral source port
        s.settimeout(interval)

        deadline_sends = 0
        while deadline_sends < repeat:
            for target in targets:
                try:
                    s.sendto(payload, (target, port))
                except OSError as e:
                    msg = f"{target}: {e}"
                    if not any(r.get("error") == msg for r in replies):
                        replies.append({"error": msg})
            deadline_sends += 1
            # Drain any replies that arrive between sends.
            try:
                while len(replies) < max_replies:
                    data, src = s.recvfrom(4096)
                    if data == payload:
                        continue  # our own broadcast echoed back
                    replies.append(_decode_reply(data, src))
            except (socket.timeout, OSError):
                pass

        s.settimeout(timeout)
        while len(replies) < max_replies:
            try:
                data, src = s.recvfrom(4096)
            except (socket.timeout, OSError):
                break
            if data == payload:
                continue  # our own broadcast echoed back
            replies.append(_decode_reply(data, src))
    return replies


def _decode_reply(data: bytes, src: tuple) -> dict[str, Any]:
    return {
        "from": f"{src[0]}:{src[1]}",
        "bytes": len(data),
        "hex": data.hex(),
        "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in data),
    }

_WS_DISCOVERY_PROBE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
    'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
    'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
    "<e:Header>"
    "<w:MessageID>uuid:00000000-0000-0000-0000-000000000001</w:MessageID>"
    "<w:To e:mustUnderstand=\"true\">"
    "urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>"
    "<w:Action e:mustUnderstand=\"true\">"
    "http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>"
    "</e:Header>"
    "<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types>"
    "</d:Probe></e:Body></e:Envelope>"
)

_SSDP_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
)


def check_ping(ip: str, timeout: float) -> bool:
    count_flag = "-n" if platform.system() == "Windows" else "-c"
    wait_flag = "-w" if platform.system() == "Windows" else "-W"
    wait_val = str(int(timeout * 1000)) if platform.system() == "Windows" else str(int(timeout))
    try:
        res = subprocess.run(
            ["ping", count_flag, "1", wait_flag, wait_val, ip],
            capture_output=True,
            text=True,
            timeout=timeout + 2,
        )
        return res.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def check_arp(ip: str) -> Optional[str]:
    """Return the camera's MAC from the ARP table, or None."""
    try:
        res = subprocess.run(
            ["arp", "-n", ip], capture_output=True, text=True, timeout=5
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    m = re.search(r"(([0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2})", res.stdout)
    if m and "incomplete" not in res.stdout.lower():
        return m.group(1)
    return None


def tcp_connect(ip: str, port: int, timeout: float) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((ip, port)) == 0


def rtsp_options(ip: str, port: int, timeout: float) -> Optional[str]:
    req = (
        f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\n"
        "CSeq: 1\r\n"
        "User-Agent: rbx-s73-probe\r\n\r\n"
    )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.sendall(req.encode())
            data = s.recv(2048)
        text = data.decode("latin-1", errors="replace").strip()
        return text or None
    except OSError:
        return None


def _multicast_probe(
    payload: bytes, addr: tuple[str, int], timeout: float, max_replies: int = 10
) -> list[dict[str, Any]]:
    replies: list[dict[str, Any]] = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.settimeout(timeout)
        try:
            s.sendto(payload, addr)
        except OSError as e:
            return [{"error": str(e)}]
        while len(replies) < max_replies:
            try:
                data, src = s.recvfrom(8192)
            except socket.timeout:
                break
            except OSError:
                break
            replies.append(
                {
                    "from": f"{src[0]}:{src[1]}",
                    "bytes": len(data),
                    "preview": data[:400].decode("latin-1", errors="replace"),
                }
            )
    return replies


def probe(
    ip: str,
    ports: list[int],
    timeout: float,
    do_discovery: bool,
) -> dict[str, Any]:
    result: dict[str, Any] = {"camera_ip": ip}

    result["ping"] = check_ping(ip, timeout)
    result["arp_mac"] = check_arp(ip)

    open_ports = []
    rtsp: dict[int, str] = {}
    for port in ports:
        if tcp_connect(ip, port, timeout):
            open_ports.append(port)
            if port in RTSP_PORTS:
                resp = rtsp_options(ip, port, timeout)
                if resp:
                    rtsp[port] = resp
    result["open_tcp_ports"] = open_ports
    result["rtsp_options"] = rtsp

    camera_discovery = False
    if do_discovery:
        ws = _annotate_replies(
            _multicast_probe(_WS_DISCOVERY_PROBE.encode(), WS_DISCOVERY_ADDR, timeout),
            ip,
        )
        ssdp = _annotate_replies(
            _multicast_probe(_SSDP_MSEARCH.encode(), SSDP_ADDR, timeout), ip
        )
        result["ws_discovery"] = ws
        result["ssdp"] = ssdp
        # Only replies FROM the camera count -- other LAN devices (router,
        # Chromecast, ...) answer these multicast probes too.
        camera_discovery = any(r.get("is_camera") for r in ws + ssdp)
    result["camera_responded_to_discovery"] = camera_discovery

    # "awake" must reflect the CAMERA, so it is based on ping/arp/its own
    # open ports / its own discovery replies -- never other devices' replies.
    result["awake"] = bool(
        result["ping"] or result["arp_mac"] or open_ports or camera_discovery
    )
    return result


def _annotate_replies(replies: list[dict[str, Any]], camera_ip: str) -> list[dict[str, Any]]:
    for rep in replies:
        src = rep.get("from", "")
        rep["is_camera"] = src.rsplit(":", 1)[0] == camera_ip
    return replies


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Non-destructive liveness/service probe for the camera.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("camera_ip", help="Camera IP address")
    p.add_argument(
        "--timeout", type=float, default=2.0, help="Per-check timeout seconds (2.0)."
    )
    p.add_argument(
        "--ports",
        help="Comma-separated TCP ports to try (overrides the default set).",
    )
    p.add_argument(
        "--no-discovery",
        dest="discovery",
        action="store_false",
        help="Skip WS-Discovery/SSDP multicast probes.",
    )
    p.add_argument(
        "--uid",
        help="Device UID (20 chars). Enables the UBIA/TUTK LAN-search probe. "
        "Treat as a secret: do not commit it.",
    )
    p.add_argument(
        "--broadcast",
        default="255.255.255.255",
        help="Broadcast address for LAN search (default 255.255.255.255).",
    )
    p.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    return p


def _print_text(r: dict[str, Any]) -> None:
    print(f"Camera {r['camera_ip']}: {'AWAKE' if r['awake'] else 'no response'}")
    print(f"  ping         : {'reply' if r['ping'] else 'no reply'}")
    print(f"  arp mac      : {r['arp_mac'] or '(not in table)'}")
    print(f"  open tcp     : {r['open_tcp_ports'] or '(none)'}")
    for port, resp in r.get("rtsp_options", {}).items():
        first_line = resp.splitlines()[0] if resp else ""
        print(f"  rtsp :{port}   : {first_line}")
    for proto, key in (("ws-discovery", "ws_discovery"), ("ssdp", "ssdp")):
        replies = r.get(key)
        if replies is None:
            continue
        cam = [x for x in replies if x.get("is_camera")]
        other = [x for x in replies if not x.get("is_camera")]
        note = "CAMERA RESPONDED" if cam else "camera silent"
        print(f"  {proto:<12} : {note} ({len(cam)} from camera, "
              f"{len(other)} from other LAN devices)")
        for rep in cam:
            print(f"      <- camera {rep.get('from')} ({rep.get('bytes')} bytes)")

    ls = r.get("lan_search")
    if ls is not None:
        cam = [x for x in ls if x.get("is_camera")]
        other = [x for x in ls if not x.get("is_camera") and "from" in x]
        note = "*** CAMERA RESPONDED ***" if cam else "no reply from camera"
        print(f"  lan-search   : {note} "
              f"({len(cam)} from camera, {len(other)} from other hosts)")
        for rep in ls:
            if "error" in rep:
                print(f"      error: {rep['error']}")
                continue
            tag = "CAMERA" if rep.get("is_camera") else "other "
            print(f"      [{tag}] {rep['from']}  {rep['bytes']} bytes")
            print(f"        hex  : {rep['hex']}")
            print(f"        ascii: {rep['ascii']}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    ports = (
        [int(x) for x in args.ports.split(",") if x.strip()]
        if args.ports
        else DEFAULT_TCP_PORTS
    )
    result = probe(args.camera_ip, ports, args.timeout, args.discovery)

    if args.uid:
        try:
            replies = lan_search(
                args.uid,
                [args.broadcast, args.camera_ip],
                max(args.timeout, 3.0),
            )
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        for rep in replies:
            src = rep.get("from", "")
            rep["is_camera"] = src.rsplit(":", 1)[0] == args.camera_ip
        result["lan_search"] = replies
        if any(r.get("is_camera") for r in replies):
            result["awake"] = True

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        _print_text(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
