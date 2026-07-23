#!/usr/bin/env python3
"""Automated first-pass recon of the UBox APK.

Decompiles with jadx (+ optionally apktool for resources/native libs) and then
answers the questions that matter for this project:

  * Which native P2P SDK is bundled? (TUTK/Kalay, CS2 PPPP, Tuya, ...)
  * Which API hostnames / endpoints does it use?
  * Where are the command IDs (pan/tilt/live/playback)?
  * Where is encryption / key derivation done?
  * Firmware / OTA endpoints?

Analysis is read-only. Only run against an APK from a device/account you own.

Examples:
    # full run (decompile + scan)
    python scripts/apk_recon.py --apk apk/ubox.apk

    # re-scan without re-decompiling (jadx is slow)
    python scripts/apk_recon.py --apk apk/ubox.apk --skip-decompile

    python scripts/apk_recon.py --apk apk/ubox.apk --json > apk/recon.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from typing import Any, Iterable, Optional

# --- Known native P2P camera SDK fingerprints -------------------------------
# name -> substrings that, if seen in lib names or strings, implicate that SDK.
SDK_SIGNATURES: dict[str, tuple[str, ...]] = {
    "TUTK / ThroughTek Kalay": (
        "IOTCAPIs", "AVAPIs", "IOTC_Connect", "avClientStart", "tutk",
        "kalay", "IOTYPE_", "st_LanSearchInfo",
    ),
    "CS2 Network PPPP": (
        "PPPP_", "PPCS_", "libPPPP", "PPCS_Connect", "P2P_Proxy",
    ),
    "Gwelltimes / iCSee (XM)": ("XMNetSDK", "XMCloud", "icsee", "gwelltimes"),
    "Tuya": ("tuyasdk", "tuya_", "libtuya"),
    "Ayla": ("aylanetworks", "libayla"),
    "HiChip": ("hichip", "libhichip"),
    "Yoosee / Jsw": ("jswsdk", "yoosee", "libjsw"),
    "Anyka": ("anyka", "libanyka"),
    "UBIA (vendor)": ("ubia", "ubianet"),
}

# Keywords from CLAUDE.md worth locating in decompiled source.
KEYWORDS: tuple[str, ...] = (
    "rtsp", "onvif", "stun", "turn", "relay", "p2p", "mqtt", "websocket",
    "firmware", "upgrade", "ota", "uid", "livestream", "playback",
    "ptz", "pantilt", "encrypt", "decrypt", "aes", "xor", "secret", "token",
)

# Things that look like command/opcode tables.
CMD_PATTERNS: tuple[str, ...] = (
    r"IOTYPE_[A-Z0-9_]+",
    r"CMD_[A-Z0-9_]+",
    r"MSG_[A-Z0-9_]+",
    r"AVIOCTRL[A-Za-z0-9_]*",
)

_HOST_RE = re.compile(
    r"\b(?:https?://)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)\b",
    re.IGNORECASE,
)
# Domains that are noise in any Android app.
_HOST_NOISE = re.compile(
    r"(^|\.)("
    r"android\.com|google\.com|googleapis\.com|gstatic\.com|w3\.org|"
    r"apache\.org|github\.com|githubusercontent\.com|json\.org|"
    r"oracle\.com|sun\.com|ietf\.org|xmlpull\.org|slf4j\.org|"
    r"example\.com|schemas\.android\.com|kotlinlang\.org|jetbrains\.com"
    r")$",
    re.IGNORECASE,
)

_TEXT_EXT = {".java", ".xml", ".json", ".txt", ".properties", ".smali", ".kt"}


# --- Pure helpers (unit-tested) ---------------------------------------------

def extract_hosts(text: str) -> set[str]:
    """Pull plausible hostnames out of a blob of text, minus common noise."""
    out: set[str] = set()
    for m in _HOST_RE.finditer(text):
        host = m.group(1).lower().rstrip(".")
        if "." not in host:
            continue
        tld = host.rsplit(".", 1)[-1]
        if not tld.isalpha() or len(tld) < 2:
            continue
        if _HOST_NOISE.search(host):
            continue
        out.add(host)
    return out


def match_sdks(haystack: Iterable[str]) -> dict[str, list[str]]:
    """Return {sdk_name: [matched signature, ...]} for any implicated SDK."""
    blob = "\n".join(haystack).lower()
    hits: dict[str, list[str]] = {}
    for sdk, sigs in SDK_SIGNATURES.items():
        matched = [s for s in sigs if s.lower() in blob]
        if matched:
            hits[sdk] = matched
    return hits


def find_commands(text: str) -> set[str]:
    out: set[str] = set()
    for pat in CMD_PATTERNS:
        out.update(re.findall(pat, text))
    return out


# --- External tools ---------------------------------------------------------

def _require(tool: str) -> str:
    path = shutil.which(tool)
    if not path:
        raise SystemExit(
            f"error: '{tool}' not found on PATH. Install it "
            f"(macOS: brew install {tool})."
        )
    return path


def run_jadx(apk: str, outdir: str) -> None:
    jadx = _require("jadx")
    print(f"[i] jadx -> {outdir} (this takes a few minutes)", file=sys.stderr)
    # jadx returns non-zero on partial failures, which are normal; keep going.
    subprocess.run(
        [jadx, "-d", outdir, "--no-debug-info", "--show-bad-code", apk],
        capture_output=True, text=True, check=False,
    )


def run_apktool(apk: str, outdir: str) -> None:
    apktool = _require("apktool")
    print(f"[i] apktool -> {outdir}", file=sys.stderr)
    subprocess.run(
        [apktool, "d", "-f", "-o", outdir, apk],
        capture_output=True, text=True, check=False,
    )


def native_libs(root: str) -> list[str]:
    out = []
    for dirpath, _, files in os.walk(root):
        for f in files:
            if f.endswith(".so"):
                out.append(os.path.join(dirpath, f))
    return sorted(out)


def lib_strings(path: str, min_len: int = 6) -> list[str]:
    """Extract printable strings from a binary without needing `strings`."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return []
    return [
        m.decode("ascii", "replace")
        for m in re.findall(rb"[ -~]{%d,}" % min_len, data)
    ]


# --- Scanning ---------------------------------------------------------------

def scan_tree(root: str, max_files: int = 60000) -> dict[str, Any]:
    keyword_hits: Counter = Counter()
    keyword_examples: dict[str, list[str]] = defaultdict(list)
    hosts: set[str] = set()
    commands: set[str] = set()
    scanned = 0

    for dirpath, _, files in os.walk(root):
        for name in files:
            if scanned >= max_files:
                break
            ext = os.path.splitext(name)[1].lower()
            if ext not in _TEXT_EXT:
                continue
            path = os.path.join(dirpath, name)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
            except OSError:
                continue
            scanned += 1
            lowered = text.lower()
            for kw in KEYWORDS:
                n = lowered.count(kw)
                if n:
                    keyword_hits[kw] += n
                    if len(keyword_examples[kw]) < 8:
                        keyword_examples[kw].append(
                            os.path.relpath(path, root)
                        )
            hosts |= extract_hosts(text)
            commands |= find_commands(text)

    return {
        "files_scanned": scanned,
        "keyword_hits": dict(keyword_hits.most_common()),
        "keyword_examples": {k: v for k, v in keyword_examples.items()},
        "hosts": sorted(hosts),
        "commands": sorted(commands),
    }


def analyze(apk: str, outbase: str, skip_decompile: bool, do_apktool: bool) -> dict:
    jadx_out = os.path.join(outbase, "jadx-output")
    apktool_out = os.path.join(outbase, "apktool-output")
    os.makedirs(outbase, exist_ok=True)

    if not skip_decompile:
        run_jadx(apk, jadx_out)
        if do_apktool:
            run_apktool(apk, apktool_out)

    result: dict[str, Any] = {"apk": apk, "jadx_output": jadx_out}

    if not os.path.isdir(jadx_out):
        raise SystemExit(f"error: no jadx output at {jadx_out}; run without --skip-decompile")

    print("[i] scanning decompiled sources...", file=sys.stderr)
    result["source_scan"] = scan_tree(jadx_out)

    libs = native_libs(jadx_out) + (
        native_libs(apktool_out) if os.path.isdir(apktool_out) else []
    )
    result["native_libs"] = [os.path.basename(p) for p in libs]

    all_strings: list[str] = []
    per_lib: dict[str, int] = {}
    for lib in libs:
        s = lib_strings(lib)
        per_lib[os.path.basename(lib)] = len(s)
        all_strings.extend(s)
    result["native_lib_string_counts"] = per_lib

    # SDK detection across lib names, lib strings, and java identifiers
    haystack = (
        [os.path.basename(p) for p in libs]
        + all_strings
        + result["source_scan"]["commands"]
        + result["source_scan"]["hosts"]
    )
    result["sdk_matches"] = match_sdks(haystack)

    lib_hosts: set[str] = set()
    for s in all_strings:
        lib_hosts |= extract_hosts(s)
    result["native_lib_hosts"] = sorted(lib_hosts)

    return result


def _print_report(r: dict) -> None:
    print("=" * 72)
    print(f"APK RECON: {r['apk']}")
    print("=" * 72)

    print("\n-- Bundled P2P SDK candidates --")
    if r["sdk_matches"]:
        for sdk, sigs in sorted(r["sdk_matches"].items(), key=lambda kv: -len(kv[1])):
            print(f"  {sdk}")
            print(f"      matched: {', '.join(sigs[:8])}")
    else:
        print("  (none matched -- inspect native libs manually)")

    print("\n-- Native libraries --")
    for lib, n in sorted(r["native_lib_string_counts"].items()):
        print(f"  {lib:<40} {n} strings")
    if not r["native_lib_string_counts"]:
        print("  (none found -- try --apktool)")

    scan = r["source_scan"]
    print(f"\n-- Hostnames in sources ({len(scan['hosts'])}) --")
    for h in scan["hosts"][:40]:
        mark = "  <== VENDOR" if "ubia" in h else ""
        print(f"  {h}{mark}")

    print(f"\n-- Hostnames in native libs ({len(r['native_lib_hosts'])}) --")
    for h in r["native_lib_hosts"][:40]:
        mark = "  <== VENDOR" if "ubia" in h else ""
        print(f"  {h}{mark}")

    print(f"\n-- Command/opcode constants ({len(scan['commands'])}) --")
    for c in scan["commands"][:60]:
        print(f"  {c}")

    print("\n-- Keyword hits --")
    for kw, n in scan["keyword_hits"].items():
        ex = scan["keyword_examples"].get(kw, [])[:3]
        print(f"  {kw:<12} {n:<6} e.g. {', '.join(ex)}")
    print()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="First-pass recon of the UBox APK (read-only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--apk", required=True, help="Path to the APK")
    p.add_argument("--out", default="apk", help="Output base dir (default: apk/)")
    p.add_argument("--skip-decompile", action="store_true",
                   help="Reuse existing jadx output")
    p.add_argument("--apktool", dest="apktool", action="store_true",
                   help="Also run apktool (gets native libs + resources)")
    p.add_argument("--json", action="store_true", help="Emit JSON")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if not os.path.isfile(args.apk):
        print(f"error: no such APK: {args.apk}", file=sys.stderr)
        return 2
    result = analyze(args.apk, args.out, args.skip_decompile, args.apktool)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        _print_report(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
