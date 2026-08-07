"""Send ioctrl queries on a relay (0x1105) session and hexdump the replies.

The relay session is the one the camera answers queries on at all — see
tools/p4p_relay.py. Default queries are the two that carry most device state.

Usage::

    .venv/bin/python tools/query_relay.py                 # 960, 816
    .venv/bin/python tools/query_relay.py 960 816 8449    # any ioTypes
"""

from __future__ import annotations

import sys

sys.path.insert(0, "tools")

from p4p_relay import open_relay_session  # noqa: E402

NAMES = {
    816: "DEVINFO_REQ", 817: "DEVINFO_RESP",
    960: "GET_ADVANCESETTINGS_REQ", 961: "GET_ADVANCESETTINGS_RESP",
    4629: "FIRMWARE_UPDATE_CHECK_REQ", 4630: "FIRMWARE_UPDATE_CHECK_RSP",
    4631: "FIRMWARE_UPDATE_REQ", 4632: "FIRMWARE_UPDATE_RSP",
}


def hexdump(data: bytes, limit: int = 1024) -> None:
    for off in range(0, min(len(data), limit), 16):
        chunk = data[off:off + 16]
        text = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        print(f"     +0x{off:03x}  {chunk.hex(' '):<47}  |{text}|")
    if len(data) > limit:
        print(f"     … {len(data) - limit} more bytes")


def main() -> int:
    iotypes = [int(a, 0) for a in sys.argv[1:]] or [960, 816]
    session = open_relay_session()
    for iotype in iotypes:
        name = NAMES.get(iotype, f"ioType {iotype}")
        print(f"\n-> {iotype} {name}")
        session.send_ioctrl(iotype, b"\x00\x00\x00\x00")
        replies = session.pump(6.0)
        if not replies:
            print("   (no reply)")
        for reply in replies:
            print(f"   <- {reply.iotype} {NAMES.get(reply.iotype, '')} "
                  f"({len(reply.data)} bytes)")
            hexdump(reply.data)
    session.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
