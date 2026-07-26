# Capture Procedure — RBX-S73

How to capture the camera's traffic with the existing gear (MikroTik RB3011,
Dell N2048P, macOS host with tshark). **No Linux VM is required.**

Camera: `192.168.88.113` on `192.168.88.0/24`. Replace the IP / interface /
port names below with your actual values.

---

## TL;DR

- You do **not** need a Linux VM. Analyze the resulting `.pcap`/flows on the Mac
  (tshark + the `p4p` tools are already installed).
- **Best method for APP / phone traffic — Method W (mitmproxy WireGuard mode).**
  The phone joins a WireGuard tunnel served by mitmproxy on the Mac, so *all*
  phone traffic routes through the Mac. In one shot you get the phone↔camera
  **local P4P** (even when phone+camera share an AP — the blind spot that defeats
  the router/switch taps) **and** the phone's **cloud HTTPS decrypted** (the app
  trusts user CAs). This was the **most successful** of the methods we tried.
- **For camera↔cloud (WAN) only:** Dell **port mirror (SPAN)** of the AP uplink →
  Mac port → `sudo tcpdump ... -w captures/xxx.pcap` (Method A), or MikroTik
  **sniffer → file** (Method B). Both are blind to same-AP phone↔camera P2P.
- **Always wake the camera first** (open UBox / trigger motion); it may drop its
  radio when idle.

> **Key result this produced (why it matters):** decoding *every* phone→camera
> P4P packet showed **zero ioctrl/command messages** — the UBox app sends **PTZ,
> motion, and light over the cloud WebSocket `ws-us.ubianet.com`, never locally**
> (local traffic is only video `0x140a`, keepalive `0x1405/0x1406`, KCP `0x1409`,
> and session-setup `0x130b–0x130d`). The cloud control WebSocket is TLS-pinned in
> a Go library that ignores user CAs, so it does **not** decrypt. Consequence:
> there is **no capturable local PTZ command** from the app — local control must
> be synthesized from the SDK, or done out-of-band (UART/thingino).

---

## Why you can't just run tcpdump on the Mac

The camera is Wi-Fi. Its packets go **camera → AP → (wired) → switch → router**.
On a switched network, a Mac in an ordinary port only receives:

- traffic addressed to the Mac, plus
- broadcast/multicast (ARP, DNS-to-broadcast, mDNS, SSDP).

It does **not** see the camera's unicast packets to the cloud. So you must
capture at a device that *is* in the camera's path (router or switch), or have
the switch **mirror** the camera's traffic to the Mac's port.

### The one blind spot that matters later

Where you tap decides what you can see:

| Capture point | Sees camera ↔ cloud (WAN) | Sees phone ↔ camera **direct on same subnet** |
|---------------|:--:|:--:|
| **Router (MikroTik)** | ✅ | ❌ if phone+camera share a subnet (traffic is routed only when crossing subnets) |
| **Switch SPAN of the AP uplink** | ✅ | ✅ **only if** the phone is *not* on the same AP (else the AP bridges it and it never reaches the uplink) |
| **Wi-Fi monitor mode** | ✅ | ✅ but payloads are WPA2-encrypted (needs PSK + handshake to decrypt) — not worth it here |

**Consequence:** For **boot / idle / cloud-dependency** work, a router-side
capture is perfect. For **live-view / pan** where we ask *"does the phone talk
directly to the camera or via a cloud relay?"*, make the phone↔camera traffic
**cross your capture point**: e.g. put the **phone on a different AP or a wired
port** (or a different VLAN) than the camera, then SPAN the AP uplink / capture
at the router. Otherwise same-AP P2P is invisible to a wired tap.

---

## Method W — mitmproxy WireGuard mode (BEST for app / phone traffic)

**The most successful method we tried.** mitmproxy runs a WireGuard server on the
Mac; the phone joins it as a VPN, so *all* phone traffic routes through the Mac.
In one shot this gives both:

- the phone↔camera **local P4P** (the Mac relays it, so it's visible even when
  phone+camera share an AP — the blind spot that defeats Methods A/B/C), and
- the phone's **cloud HTTPS, decrypted** (the UBox app trusts user CAs).

Unlike an explicit HTTP proxy — which broke the app's third-party SDK startup (it
hung at the splash screen) — WireGuard mode intercepts at the network layer and
passes non-MITM'd flows through, so **the app runs normally**.

1. Start mitmproxy in WireGuard mode (repo `.venv`, mitmproxy 12.2.3). First run
   generates the WG keypair at `~/.mitmproxy/wireguard.conf` and prints a **QR
   code** + client config (Endpoint = `<Mac-LAN-IP>:51820`):

   ```bash
   .venv/bin/mitmweb --mode wireguard                          # web UI, or:
   .venv/bin/mitmdump --mode wireguard -w captures/app.flows   # headless + save flows
   ```

2. **Phone:** install the **WireGuard** app → scan the QR (or import
   `wireguard.conf`) → enable the tunnel. All phone traffic now flows via the Mac.

3. **(Decrypt cloud HTTPS)** On the phone, open **mitm.it** through the tunnel and
   install + trust the mitmproxy CA. The app's `network_security_config` trusts
   user CAs (`src=user`, `overridePins=true`), so `portal.ubianet.com` decrypts.
   The `ws-us.ubianet.com` control WebSocket does **not** (its Go TLS stack ignores
   user CAs).

4. **Capture on the Mac — two streams:**
   - *Local P4P* (phone↔camera): the Mac relays it, so a plain LAN capture catches
     it — decode with the `p4p` tools:
     ```bash
     export PATH="/opt/homebrew/bin:$PATH"
     sudo tcpdump -i en0 host <CAMERA_IP> -w captures/app-p4p.pcap
     ```
   - *Cloud HTTPS*: watch live in mitmweb, or read the saved flows:
     `.venv/bin/mitmproxy -r captures/app.flows`.

5. Perform the scenario (live view → pan → light) while capturing. Confirm the
   WireGuard app shows a recent handshake + byte counts so you know it's routing.

> **Security:** `~/.mitmproxy/wireguard.conf` + the CA hold **private keys**, and
> saved `.flows` contain **decrypted tokens** (`x-ubia-auth-usertoken`). Keep all
> of it out of git (`captures/` is already ignored; never commit `wireguard.conf`,
> the CA, or `.flows`). Don't paste WG keys or the Wi-Fi password into chat.

**Payoff this produced:** decoding every phone→camera P4P packet → **zero ioctrl**
(app does PTZ/motion/light via the cloud WebSocket, never locally); decrypting
`portal.ubianet.com` → firmware **2455.0.21.10** (Ingenic T31), no OTA for an
up-to-date device. See the key-result note in the TL;DR.

---

## Method A — Dell N2048P port mirror → Mac (WAN-side only)

Best signal quality: the Mac receives a copy of raw Ethernet frames.

1. Identify the switch port carrying the camera's traffic — usually the **uplink
   of the AP the camera is joined to** (or the router uplink). Call it the
   *source*. Plug the Mac into a spare port — the *destination*.
2. On the Dell (N-series CLI; confirm exact syntax for your firmware):

   ```
   enable
   configure
   monitor session 1 source interface gigabitethernet 1/0/10   ! AP uplink
   monitor session 1 destination interface gigabitethernet 1/0/24  ! Mac port
   monitor session 1 mode
   end
   show monitor session 1
   ```

   The destination port becomes capture-only (no normal traffic) while active.
3. On the Mac, find the wired interface and capture (see “Capturing on the Mac”).
4. When done: `configure` → `no monitor session 1`.

> The Dell N2048P is **PoE** — if the camera's AP is powered from this switch,
> don't disturb its port. Mirror the AP *uplink*, not the camera.

---

## Method B — MikroTik sniffer → file (no extra host)

The router captures to its own storage; you download the `.pcap`. Router-side,
so mind the blind spot above. Good for boot/idle. Keep captures short (RB3011
storage is limited; idle/boot are only a few MB).

```rsc
# Capture only the camera's packets, to a file on the router
/tool sniffer set filter-ip-address=192.168.88.113/32 \
    file-name=rbx-idle.pcap file-limit=20000
/tool sniffer start
#   ... perform the scenario (reboot camera / let it idle) ...
/tool sniffer stop
/file print where name~"rbx"
```

Download `rbx-idle.pcap` (WinBox: Files → drag out; or `scp`/FTP from the
router) into `captures/`.

> ⚠️ **Duplicate frames.** Observed in practice: the sniffer recorded **every
> frame twice** (once on ingress, once on egress), inflating packet/byte counts
> ~2×. Either pin a single interface:
>
> ```rsc
> /tool sniffer set filter-interface=bridge   # or the specific ether port
> ```
>
> or dedupe after downloading:
>
> ```bash
> editcap -d captures/rbx-idle.pcap captures/rbx-idle-dedup.pcap
> ```
>
> Always sanity-check with `capinfos` before trusting absolute numbers.

*Notes:* `file-limit` is in KB. `filter-ip-address` keeps the file small. To
also catch DHCP/DNS at boot you can widen the filter or add
`filter-ip-address=192.168.88.113/32,192.168.88.1/32`.

---

## Next capture: live view / pan (ready-to-paste)

**Setup first — this matters:** put the **phone on a different AP or VLAN than
the camera**. If they share an AP, direct phone↔camera P2P is bridged inside
the AP and never reaches the router, so a router-side capture cannot tell
"direct P2P" from "cloud relay" — the exact question this capture must answer.

```rsc
# 0. Check headroom -- a video capture is much bigger than the idle one
/system resource print
# 0b. Find the phone's IP
/ip dhcp-server lease print

# 1. Configure: camera + phone, ONE interface (avoids the duplicate-frame
#    artifact), write to file
/tool sniffer set filter-ip-address=192.168.88.113/32,<PHONE_IP>/32 \
    filter-interface=bridge \
    streaming-enabled=no \
    file-name=rbx-live.pcap file-limit=30000

# 2. Capture ONE action
/tool sniffer start
#      -> in UBox: open live view, watch ~60s, close it
/tool sniffer stop

# 3. Second capture isolating PAN
/tool sniffer set file-name=rbx-pan.pcap
/tool sniffer start
#      -> open live view, then press PAN only
/tool sniffer stop

/file print where name~"rbx"
```

`file-limit` is in **KB** (30000 ≈ 30 MB). If free space is tight, shorten the
live view or use Method C (stream to the Mac) instead.

Download and analyze:

```bash
scp -O admin@192.168.88.1:rbx-live.pcap captures/
scp -O admin@192.168.88.1:rbx-pan.pcap  captures/

export PATH="/opt/homebrew/bin:$PATH"
.venv/bin/python scripts/compare_sessions.py \
    idle=captures/rbx-idle.pcap \
    live=captures/rbx-live.pcap \
    pan=captures/rbx-pan.pcap \
    --camera-ip 192.168.88.113
```

---

## Method E — Wi-Fi monitor capture on the Mac (for phone↔camera direct P2P)

The live AV session is bridged in the Wi-Fi AP (invisible to router/switch), so
to capture it we sniff 802.11 over the air and decrypt with the WLAN passphrase.

Setup facts (this network): camera is 2.4 GHz-only, MAC `84:1d:e8:0e:b2:50`, on
**channel 4** (the Mac associates there); Wi-Fi interface `en0`.

1. **Sniff (built-in macOS tool, no install):** Option-click the Wi-Fi menu bar
   icon → *Open Wireless Diagnostics…* → menu *Window → Sniffer* → Channel **4**,
   Width **20 MHz** → *Start*. (The Mac drops off Wi-Fi while sniffing.) It saves
   a `.pcap` (shows the path on stop; usually Desktop or `/var/tmp`).
2. **Force handshakes + traffic** during the sniff (needed to decrypt): toggle
   the **phone** Wi-Fi off/on; power-cycle the **camera** if easy; then open
   **live view + pan ~60 s** in UBox. Stop the sniffer.
3. **Decrypt locally** (keeps the passphrase on your machine):
   ```bash
   airdecap-ng -e "SSID" -p "WIFI_PASSWORD" /path/to/sniff.pcap   # -> sniff-dec.pcap
   ```
4. Copy the decrypted pcap into `captures/` for analysis.
5. **Verify** if a decrypt looks empty:
   ```bash
   tshark -r sniff.pcap -Y eapol | wc -l                          # want >=4 (handshakes)
   tshark -r sniff.pcap -Y 'wlan.addr==84:1d:e8:0e:b2:50' | head  # camera present?
   ```
   If the camera is absent, it's on another channel — retry the sniffer on 1/6/11.

Fallback if the built-in Sniffer is unavailable: `brew install --cask wireshark`
(monitor mode + channel selector + live decryption in the GUI).

## Method C — MikroTik sniffer → live stream to Wireshark on the Mac

Router streams matching packets (TZSP, UDP/37008) to the Mac; Wireshark
auto-decapsulates TZSP and shows the inner packets.

```rsc
/tool sniffer set streaming-enabled=yes streaming-server=<MAC_IP> \
    filter-stream=yes filter-ip-address=192.168.88.113/32
/tool sniffer start
#   ... perform scenario ...
/tool sniffer stop
```

Receive on the Mac. This is the one method that benefits from the **Wireshark
GUI** (it unwraps TZSP cleanly): `brew install --cask wireshark`, then capture
on the interface receiving the stream and “Save As” a `.pcap`. (Our analysis
tools also read TZSP-wrapped captures — tshark still dissects the inner IP — but
frame sizes then include TZSP overhead, so a clean capture from Method A/B is
preferred.)

---

## Capturing on the Mac (Methods A & C save-side)

```bash
# List interfaces (wired dock/adapter is often en5/en6/en7)
ifconfig -l
# or: tshark -D

# Capture to a clean pcap (Ctrl-C to stop). No root needed for tshark on an
# interface you own; tcpdump needs sudo.
sudo tcpdump -i en5 -w captures/rbx-s73-idle.pcap
# Optional narrow filter once you trust the tap:
sudo tcpdump -i en5 host 192.168.88.113 -w captures/rbx-s73-idle.pcap
```

Verify the capture actually contains camera traffic before trusting it:

```bash
capinfos captures/rbx-s73-idle.pcap
tshark -r captures/rbx-s73-idle.pcap -Y 'ip.addr==192.168.88.113' -c 5
```

---

## Scenario checklist & file naming

Wake the camera first. One file per scenario, named `rbx-s73-<scenario>.pcap`
in `captures/` (git-ignored). Capture each for long enough to see steady state
(idle: ~2–3 min to catch the keepalive cadence).

| # | Scenario | Suggested filename |
|---|----------|--------------------|
| 1 | Camera boot (power-on) | `rbx-s73-boot.pcap` |
| 2 | Idle (2–3 min) | `rbx-s73-idle.pcap` |
| 3 | UBox app startup | `rbx-s73-app-startup.pcap` |
| 4 | Open live view | `rbx-s73-live-open.pcap` |
| 5 | Close live view | `rbx-s73-live-close.pcap` |
| 6 | Pan | `rbx-s73-pan.pcap` |
| 7 | Tilt | `rbx-s73-tilt.pcap` |
| 8 | Two-way audio | `rbx-s73-audio.pcap` |
| 9 | Motion trigger | `rbx-s73-motion.pcap` |
| 10 | SD-card playback | `rbx-s73-sd-playback.pcap` |
| 11 | Camera WAN blocked | `rbx-s73-wanblock.pcap` |

Keep each capture to a **single action** where possible — that is what makes
`compare_sessions.py` able to isolate the flow/command a given action adds.

---

## Then analyze

```bash
export PATH="/opt/homebrew/bin:$PATH"   # tshark

.venv/bin/python scripts/summarize_pcap.py captures/rbx-s73-idle.pcap \
    --camera-ip 192.168.88.113
.venv/bin/python scripts/extract_dns.py captures/rbx-s73-boot.pcap \
    --camera-ip 192.168.88.113
.venv/bin/python scripts/compare_sessions.py \
    idle=captures/rbx-s73-idle.pcap \
    live=captures/rbx-s73-live-open.pcap \
    --camera-ip 192.168.88.113
```

Record findings in `research-log.md`; update `network-behavior.md` /
`cloud-dependencies.md` as the picture fills in.
