# Capture Procedure — RBX-S73

How to capture the camera's traffic with the existing gear (MikroTik RB3011,
Dell N2048P, macOS host with tshark). **No Linux VM is required.**

Camera: `192.168.88.113` on `192.168.88.0/24`. Replace the IP / interface /
port names below with your actual values.

---

## TL;DR

- You do **not** need a Linux VM. Capture with the MikroTik or the Dell switch;
  analyze the resulting `.pcap` on the Mac (tshark is already installed).
- **Primary method:** Dell **port mirror (SPAN)** of the camera's AP uplink →
  a Mac port → `sudo tcpdump ... -w captures/xxx.pcap`. Raw frames, no
  encapsulation.
- **No-extra-host fallback:** MikroTik **sniffer → file**, then download the
  `.pcap`. Router-side, so it has one blind spot (below).
- **Always wake the camera first** (open UBox / trigger motion); it may drop its
  radio when idle.

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

## Method A — Dell N2048P port mirror → Mac (recommended)

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
