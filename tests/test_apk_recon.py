"""Unit tests for the pure helpers in apk_recon."""

from __future__ import annotations

from apk_recon import extract_hosts, find_commands, match_sdks


def test_extract_hosts_finds_vendor_and_drops_noise():
    text = """
        String base = "https://portal.us.ubianet.com/api/v1/login";
        String p2p  = "m7.ubianet.com";
        import android.content.Context;   // schemas.android.com noise
        <manifest xmlns:android="http://schemas.android.com/apk/res/android">
        see http://www.w3.org/2000/svg and apache.org
    """
    hosts = extract_hosts(text)
    assert "portal.us.ubianet.com" in hosts
    assert "m7.ubianet.com" in hosts
    # noise domains filtered out
    assert not any(h.endswith("android.com") for h in hosts)
    assert "w3.org" not in hosts
    assert "apache.org" not in hosts


def test_extract_hosts_ignores_non_hosts():
    assert extract_hosts("just some words, 1.2, a.b") <= {"a.b"}
    assert extract_hosts("") == set()


def test_match_sdks_detects_tutk():
    hay = ["libIOTCAPIs.so", "avClientStart", "IOTYPE_USER_IPCAM_START"]
    hits = match_sdks(hay)
    assert "TUTK / ThroughTek Kalay" in hits


def test_match_sdks_detects_pppp_and_vendor():
    hits = match_sdks(["libPPPP.so", "PPCS_Connect", "ubianet.com"])
    assert "CS2 Network PPPP" in hits
    assert "UBIA (vendor)" in hits


def test_match_sdks_empty_when_nothing_matches():
    assert match_sdks(["libc.so", "hello world"]) == {}


def test_find_commands_extracts_opcode_constants():
    text = """
        public static final int IOTYPE_USER_IPCAM_PTZ_COMMAND = 4097;
        static final int CMD_START_LIVE = 0x10;
        MSG_PLAYBACK_START, AVIOCTRLDEFs
    """
    cmds = find_commands(text)
    assert "IOTYPE_USER_IPCAM_PTZ_COMMAND" in cmds
    assert "CMD_START_LIVE" in cmds
    assert "MSG_PLAYBACK_START" in cmds
    assert any(c.startswith("AVIOCTRL") for c in cmds)


def test_find_commands_empty():
    assert find_commands("nothing interesting here") == set()
