# SEHMUA RBX-S73 Local Camera Reverse-Engineering Project

## Objective

Reverse-engineer a SEHMUA RBX-S73 solar-powered Wi-Fi security camera so it can be used locally without access to the manufacturer’s cloud services.

The preferred outcome is to expose the camera to Home Assistant as a basic IP camera through one of the following:

1. RTSP
2. ONVIF
3. A local HTTP/MJPEG stream
4. A custom local proxy that converts the proprietary camera protocol into RTSP or another Home Assistant-compatible format

After local access is working, the camera will be isolated from the Internet so it cannot phone home.

## Device Information

* Manufacturer: SEHMUA
* Model: RBX-S73
* Type: Solar-powered, battery-operated, pan/tilt Wi-Fi camera
* Mobile app: UBox
* Network: 2.4 GHz Wi-Fi
* Storage: microSD and optional vendor cloud storage
* Known documentation does not advertise RTSP, ONVIF, or a local API
* The camera may sleep when idle to conserve battery

## Existing Infrastructure

The network includes:

* MikroTik RB3011UiAS router
* Dell N2048P managed PoE switch
* Home Assistant
* Linux servers capable of running:

  * Wireshark
  * tcpdump
  * nmap
  * Python
  * Docker
  * go2rtc
  * Frigate
  * ffmpeg
* VLAN support and configurable firewall rules
* Ability to mirror switch ports or capture traffic at the router

The camera can eventually be placed on a dedicated IoT or camera VLAN.

## Current Findings

A TCP scan against the camera did not reveal any listening services.

Tests already performed include scans comparable to:

```bash
nmap -Pn -sV -A CAMERA_IP
nmap -Pn -p- CAMERA_IP
```

No useful open ports were found.

This suggests one or more of the following:

* The camera exposes no conventional TCP server
* The camera sleeps when idle
* The camera only initiates outbound connections
* Live video uses a proprietary UDP protocol
* The UBox app performs cloud-assisted peer-to-peer session setup
* The camera relies completely on a cloud relay
* Services are only enabled briefly while the camera is awake

Do not assume that the lack of open ports means there is no local communication path.

## Immediate Investigation Plan

The next stage is passive network observation.

Capture camera traffic during several clearly labeled scenarios:

1. Camera boot
2. Camera idle
3. UBox app startup
4. Opening live view
5. Closing live view
6. Pan command
7. Tilt command
8. Two-way audio, if available
9. Triggering motion
10. Playing an SD-card recording
11. Camera operating with Internet access blocked

Packet captures may be created through:

* A mirrored Dell switch port
* MikroTik packet capture
* tcpdump on a suitable bridge, router, or monitoring host

Example:

```bash
sudo tcpdump -i INTERFACE host CAMERA_IP -w rbx-s73-live-view.pcap
```

The camera should be woken immediately before active scans or captures because it may disable its radio or services while sleeping.

## Questions the Analysis Must Answer

For each capture, determine:

1. Which DNS names the camera resolves
2. Which remote IP addresses and ports it contacts
3. Whether it uses TCP, UDP, QUIC, STUN, TURN, MQTT, HTTPS, or another protocol
4. Whether the phone talks directly to the camera
5. Whether the phone and camera communicate through a relay
6. Whether cloud access is needed only for authentication or session setup
7. Whether video packets travel directly between phone and camera
8. Whether video is encrypted
9. Whether control commands and video use different channels
10. Whether there is a repeatable packet sequence that wakes or activates the camera
11. Whether LAN-only operation works after cloud-assisted initialization
12. Whether the camera maintains a persistent outbound control connection
13. Whether any local multicast or broadcast discovery occurs
14. Whether the protocol resembles an existing P2P camera platform

## Capture Analysis Priorities

Inspect for:

* DNS
* DHCP
* NTP
* ARP
* mDNS
* SSDP
* WS-Discovery
* STUN
* TURN
* ICE-like negotiation
* MQTT
* WebSocket
* TLS
* QUIC
* DTLS
* RTP or RTCP
* Proprietary high-volume UDP traffic
* Periodic keepalive traffic
* NAT traversal behavior

Useful Wireshark filters include:

```text
ip.addr == CAMERA_IP
dns
stun
rtp
rtcp
quic
tls
udp
tcp
```

Also inspect:

* Packet sizes
* Timing
* Directionality
* Repeated headers
* Sequence counters
* Session identifiers
* Entropy
* Whether payloads remain similar across repeated commands

## Internet-Blocking Experiment

Test the camera under these conditions:

### Test A: Fully online

* Camera has normal Internet access
* Phone has normal Internet access
* Phone is on the same LAN as the camera

### Test B: Camera WAN blocked

* Camera can access the local network
* Camera cannot access the Internet
* Phone can access both the Internet and the camera LAN

### Test C: Phone WAN blocked

* Phone can access the camera locally
* Phone cannot access the Internet
* Camera remains online

### Test D: Both WAN blocked

* Phone and camera can communicate locally
* Neither can access the Internet

Record whether the following work in each test:

* Device status
* Live view
* Pan and tilt
* Audio
* Motion notifications
* SD-card playback

This matrix should reveal whether the cloud is used for discovery, authentication, signaling, relay, or all communication.

## UBox App Investigation

If packet captures are insufficient, inspect the Android version of the UBox app.

Potential tasks:

1. Obtain the APK from a legally accessible source or an owned Android device
2. Decompile it using JADX
3. Inspect bundled native libraries
4. Search strings and symbols for:

   * RTSP
   * ONVIF
   * P2P
   * UID
   * STUN
   * TURN
   * relay
   * stream
   * live
   * playback
   * device login
   * firmware
   * OTA
   * MQTT
   * WebSocket
   * camera commands
   * known SDK vendor names
5. Identify API hostnames
6. Identify device authentication flow
7. Identify P2P SDK libraries
8. Locate command IDs for pan, tilt, wake, live view, and playback
9. Locate encryption or key-derivation routines
10. Locate firmware update endpoints

Useful commands may include:

```bash
jadx -d jadx-output UBox.apk
apktool d UBox.apk -o apktool-output
grep -RniE "rtsp|onvif|stun|turn|relay|p2p|mqtt|firmware|upgrade|ota" jadx-output apktool-output
```

For native libraries:

```bash
find apktool-output -name "*.so" -print
strings path/to/library.so | less
readelf -Ws path/to/library.so
nm -D path/to/library.so
```

Do not assume Java code contains the important protocol logic. Many camera apps bundle a proprietary native P2P SDK.

## TLS and API Inspection

If the app communicates with HTTPS APIs, investigate only traffic from devices and accounts I own.

Possible approaches:

* Android emulator
* A test Android device
* mitmproxy
* Burp Suite
* Frida, when certificate pinning prevents inspection

First determine whether certificate pinning is present.

If API traffic can be observed, document:

* Authentication endpoints
* Device registration
* Device UID format
* Session-token issuance
* P2P negotiation responses
* Relay-server assignment
* Firmware metadata
* Configuration endpoints

Never commit account credentials, device secrets, private keys, tokens, or packet captures containing sensitive data.

Use `.gitignore` for:

```gitignore
*.pcap
*.pcapng
*.apk
secrets/
captures/
firmware/
.env
```

## Firmware Investigation

Look for OTA requests during boot, app startup, or device settings access.

Record:

* Firmware version
* Update-check endpoint
* Download URL
* File size
* Hash
* Signature information
* Compression format
* Encryption status

If firmware is obtained legally from the vendor update mechanism, analyze it with:

```bash
file firmware.bin
binwalk firmware.bin
binwalk -eM firmware.bin
strings firmware.bin
```

Search extracted contents for:

```text
rtsp
onvif
live555
gstreamer
ffmpeg
boa
lighttpd
nginx
busybox
telnetd
dropbear
udhcp
wpa_supplicant
mqtt
stun
turn
p2p
554
8554
```

Also inspect:

* Init scripts
* Network configuration
* Disabled daemons
* Debug interfaces
* Hard-coded credentials
* Public keys
* Update verification logic
* SoC vendor
* Kernel version
* Filesystem layout

## Hardware Investigation

Only proceed to hardware work if software investigation is inconclusive.

Potential tasks:

1. Photograph all PCB markings
2. Identify the SoC
3. Identify flash storage
4. Identify UART pads
5. Identify test pads
6. Determine UART voltage before attaching an adapter
7. Capture boot output using a 3.3 V USB-to-UART adapter
8. Do not connect the adapter’s VCC line
9. Connect only:

   * Ground
   * Camera TX to adapter RX
   * Camera RX to adapter TX only when needed

Common baud rates:

```text
115200
57600
38400
9600
```

Avoid writing to flash until a complete backup exists.

Potential flash access methods may include:

* Bootloader commands
* UART shell
* SPI flash clip
* NAND extraction
* Vendor recovery mode

## Desired Deliverables

Create a repository containing:

```text
rbx-s73-research/
├── README.md
├── CLAUDE.md
├── docs/
│   ├── device-profile.md
│   ├── network-behavior.md
│   ├── protocol-notes.md
│   ├── cloud-dependencies.md
│   ├── firmware-analysis.md
│   └── hardware-notes.md
├── scripts/
│   ├── summarize_pcap.py
│   ├── extract_dns.py
│   ├── compare_sessions.py
│   ├── udp_flow_report.py
│   └── probe_camera.py
├── wireshark/
│   └── display-filters.txt
├── integrations/
│   ├── go2rtc/
│   ├── home-assistant/
│   └── frigate/
├── tests/
├── captures/
│   └── .gitkeep
├── firmware/
│   └── .gitkeep
└── .gitignore
```

## Initial Coding Tasks

Build safe, read-only analysis tools before attempting protocol emulation.

### 1. PCAP summary tool

Create a Python script that accepts a PCAP or PCAPNG file and reports:

* Capture duration
* Camera IP
* Protocol counts
* Local and remote endpoints
* TCP ports
* UDP ports
* DNS queries and answers
* TLS SNI names, where visible
* Flow byte counts
* Packet-size distributions
* Suspected keepalive flows
* High-bandwidth flows likely to contain video

Preferred implementation:

* Python 3.11+
* Type hints
* argparse
* Clear error handling
* Unit tests
* Scapy, dpkt, pyshark, or tshark subprocesses

Do not require root privileges merely to analyze an existing capture.

### 2. Session comparison tool

Create a tool that compares captures from:

* Idle
* Live view
* Pan
* Tilt
* WAN blocked

Highlight flows and payload patterns that appear only during each action.

### 3. UDP payload analysis

For candidate proprietary UDP flows, report:

* Payload lengths
* First bytes in hex
* Repeating headers
* Sequence-like integer fields
* Timestamps
* Entropy estimates
* Directional differences
* Packet-loss or retransmission patterns

Avoid printing complete sensitive payloads by default.

### 4. Camera probe tool

Create a non-destructive probe utility that can:

* Ping or ARP-check the camera
* Run selected TCP connection attempts
* Send ONVIF WS-Discovery probes
* Send SSDP discovery
* Test common RTSP ports
* Record whether the camera is awake
* Avoid brute-force credential attempts
* Avoid malformed fuzzing packets

## Home Assistant Integration Targets

Preferred target order:

1. Native ONVIF integration
2. Generic Camera integration
3. go2rtc restream
4. Frigate camera input
5. Custom Home Assistant integration
6. Local daemon that translates the proprietary protocol to RTSP

If a custom proxy is needed, prefer:

* A small Linux daemon
* Docker support
* Configurable credentials through environment variables or secrets files
* Structured logging
* Automatic reconnect
* Health endpoint
* Optional RTSP output via go2rtc or MediaMTX
* No cloud dependency

Potential architecture:

```text
RBX-S73 camera
      |
Proprietary local/P2P protocol
      |
Custom bridge daemon
      |
go2rtc or MediaMTX
      |
RTSP / WebRTC
      |
Home Assistant or Frigate
```

## Security Requirements

* Work only with the camera, mobile device, account, and network I own
* Do not scan unrelated public IP addresses
* Do not attempt to access vendor systems beyond normal client behavior
* Do not perform credential stuffing or brute-force attacks
* Do not publish device credentials, tokens, keys, or personally identifying capture data
* Redact MAC addresses, public IP addresses, account identifiers, and device UIDs before publishing
* Prefer passive observation over active exploitation
* Back up firmware before modifying anything
* Make no irreversible device changes without an explicit recovery plan

## Network Lockdown Goal

Once local operation is proven, the final firewall policy should be approximately:

```text
Allow Home Assistant/NVR -> Camera on required local ports
Allow Camera -> Home Assistant/NVR only if required
Allow Camera -> local DNS only if required
Allow Camera -> local NTP only if required
Block Camera -> all WAN destinations
Block Camera -> other LAN VLANs
Block unsolicited LAN clients -> Camera
Log rejected camera WAN attempts during testing
```

The camera should receive a static DHCP lease.

Do not apply permanent WAN-block rules until the exact cloud dependency has been documented, because blocking access too early may interfere with packet-capture analysis.

## Working Method

For each finding:

1. Record the test conditions
2. Preserve the exact command used
3. Save raw output
4. Separate observed facts from hypotheses
5. Note confidence level
6. Propose the smallest next experiment that distinguishes competing hypotheses
7. Avoid prematurely deciding the device is cloud-only
8. Avoid assuming encrypted traffic is impossible to reproduce
9. Avoid making irreversible hardware or firmware modifications

When analyzing evidence, clearly label conclusions as:

* Confirmed
* Strongly indicated
* Possible
* Unknown

The immediate next task is to create the repository structure and implement the PCAP summary and session-comparison tools. Do not attempt protocol emulation until actual packet captures are available.
