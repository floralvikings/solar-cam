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


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    ports = (
        [int(x) for x in args.ports.split(",") if x.strip()]
        if args.ports
        else DEFAULT_TCP_PORTS
    )
    result = probe(args.camera_ip, ports, args.timeout, args.discovery)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        _print_text(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
