"""Thin, streaming wrapper around the ``tshark`` CLI.

Design goals:

* No root required -- we only *read* existing capture files.
* Stream packets line-by-line so multi-gigabyte video captures do not
  have to be held in memory.
* Keep the tshark invocation in exactly one place; everything else in the
  package operates on :class:`PacketRow` objects.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Iterator
from typing import Optional

from .model import PacketRow

# Order matters: this list is passed to `-e` flags and the output columns
# come back in the same order.
_FIELDS: tuple[str, ...] = (
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "_ws.col.Protocol",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "ip.proto",
    "udp.srcport",
    "udp.dstport",
    "tcp.srcport",
    "tcp.dstport",
    "dns.qry.name",
    "dns.a",
    "dns.aaaa",
    "dns.cname",
    "tls.handshake.extensions_server_name",
)

_PAYLOAD_FIELDS: tuple[str, ...] = ("udp.payload", "tcp.payload")

# ip.proto number -> our short l4 label, used when there is no udp/tcp port.
_PROTO_NUMS = {"1": "icmp", "2": "igmp", "6": "tcp", "17": "udp", "58": "icmpv6"}


class TsharkNotFound(RuntimeError):
    """Raised when the tshark binary cannot be located."""


class TsharkError(RuntimeError):
    """Raised when tshark exits non-zero (bad file, bad filter, ...)."""


def find_tshark(explicit: Optional[str] = None) -> str:
    """Return a usable tshark path or raise :class:`TsharkNotFound`."""
    candidate = explicit or shutil.which("tshark")
    if candidate and shutil.which(candidate):
        return candidate
    if explicit:
        raise TsharkNotFound(f"tshark not found at: {explicit!r}")
    raise TsharkNotFound(
        "tshark is not on PATH. Install Wireshark's CLI "
        "(macOS: `brew install wireshark`, Debian/Ubuntu: "
        "`sudo apt install tshark`), or pass --tshark /path/to/tshark."
    )


def tshark_version(tshark_bin: Optional[str] = None) -> str:
    binary = find_tshark(tshark_bin)
    out = subprocess.run(
        [binary, "--version"], capture_output=True, text=True, check=False
    )
    return (out.stdout or out.stderr).splitlines()[0].strip()


def _to_int(value: str) -> Optional[int]:
    value = value.strip()
    if not value:
        return None
    # A field like udp.srcport can occasionally repeat (tunnels); take first.
    if "," in value:
        value = value.split(",", 1)[0]
    try:
        return int(value)
    except ValueError:
        return None


def _first(value: str) -> Optional[str]:
    value = value.strip()
    if not value:
        return None
    return value.split(",", 1)[0]


def _multi(value: str) -> tuple[str, ...]:
    value = value.strip()
    if not value:
        return ()
    return tuple(v for v in value.split(",") if v)


def _hex_to_bytes(value: str) -> Optional[bytes]:
    value = value.strip().replace(":", "")
    if not value:
        return None
    try:
        return bytes.fromhex(value)
    except ValueError:
        return None


def _build_command(
    binary: str,
    pcap_path: str,
    fields: tuple[str, ...],
    display_filter: Optional[str],
) -> list[str]:
    cmd = [
        binary,
        "-r",
        pcap_path,
        "-n",  # no name resolution: faster, deterministic, no live DNS
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=a",  # all occurrences of a repeated field...
        "-E",
        "aggregator=,",  # ...joined by comma
        "-E",
        "quote=n",
        "-E",
        "header=n",
    ]
    for f in fields:
        cmd += ["-e", f]
    if display_filter:
        cmd += ["-Y", display_filter]
    return cmd


def read_packets(
    pcap_path: str,
    *,
    display_filter: Optional[str] = None,
    include_payload: bool = False,
    tshark_bin: Optional[str] = None,
) -> Iterator[PacketRow]:
    """Yield one :class:`PacketRow` per packet in ``pcap_path``.

    Streams tshark's output, so memory use stays flat regardless of file
    size. Raises :class:`TsharkNotFound` / :class:`TsharkError` on failure.
    """
    binary = find_tshark(tshark_bin)
    fields = _FIELDS + (_PAYLOAD_FIELDS if include_payload else ())
    cmd = _build_command(binary, pcap_path, fields, display_filter)

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    assert proc.stdout is not None
    try:
        for line in proc.stdout:
            row = _parse_line(line.rstrip("\n"), include_payload)
            if row is not None:
                yield row
    finally:
        proc.stdout.close()
        stderr = proc.stderr.read() if proc.stderr else ""
        code = proc.wait()
        if code != 0:
            raise TsharkError(
                f"tshark exited {code} for {pcap_path!r}: {stderr.strip()}"
            )


def _parse_line(line: str, include_payload: bool) -> Optional[PacketRow]:
    if not line:
        return None
    cols = line.split("\t")
    n_base = len(_FIELDS)
    # Pad in case trailing empty fields were dropped.
    while len(cols) < n_base + (len(_PAYLOAD_FIELDS) if include_payload else 0):
        cols.append("")

    (
        num,
        tepoch,
        flen,
        proto_col,
        ip_src,
        ip_dst,
        ip6_src,
        ip6_dst,
        ip_proto,
        udp_sport,
        udp_dport,
        tcp_sport,
        tcp_dport,
        dns_q,
        dns_a,
        dns_aaaa,
        dns_cname,
        sni,
    ) = cols[:n_base]

    number = _to_int(num) or 0
    try:
        time = float(tepoch) if tepoch.strip() else 0.0
    except ValueError:
        time = 0.0
    length = _to_int(flen) or 0

    src = _first(ip_src) or _first(ip6_src)
    dst = _first(ip_dst) or _first(ip6_dst)

    if udp_sport.strip() or udp_dport.strip():
        l4: Optional[str] = "udp"
        srcport = _to_int(udp_sport)
        dstport = _to_int(udp_dport)
    elif tcp_sport.strip() or tcp_dport.strip():
        l4 = "tcp"
        srcport = _to_int(tcp_sport)
        dstport = _to_int(tcp_dport)
    else:
        l4 = _PROTO_NUMS.get(_first(ip_proto) or "")
        srcport = None
        dstport = None

    answers = _multi(dns_a) + _multi(dns_aaaa) + _multi(dns_cname)

    payload: Optional[bytes] = None
    if include_payload:
        pay_cols = cols[n_base : n_base + len(_PAYLOAD_FIELDS)]
        for raw in pay_cols:
            b = _hex_to_bytes(raw)
            if b:
                payload = b
                break

    return PacketRow(
        number=number,
        time=time,
        length=length,
        src=src,
        dst=dst,
        l4=l4,
        srcport=srcport,
        dstport=dstport,
        protocol=_first(proto_col),
        dns_query=_first(dns_q),
        dns_answers=answers,
        sni=_first(sni),
        payload=payload,
    )
