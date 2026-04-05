# Project 04 — Professional Deep-Packet Inspection Sniffer

**Author: Kuldeep Singh**

---

**Custom deep-packet inspection (DPI) engine built on raw sockets—eliminating dependencies on Scapy or libpcap to achieve direct kernel-level packet processing.**

## Security Researcher Perspective

In-depth protocol analysis is the foundation of network forensics and intrusion detection. This tool implements a **Protocol-Aware Decoding Stack**, manualizing the deserialization of Ethernet, IP, TCP, UDP, ICMP, and DNS layers. It goes beyond simple capture by providing **Stateful TCP Tracking** and **Heuristic Anomaly Detection**, enabling researchers to identify port scans and ARP spoofing in real-time without proprietary commercial tools.

## Technical Differentiators

| Feature | Standard Sniffer | This DPI Sniffer |
|---------|--------------|--------------|
| **Decoding Depth** | IP/Port only | **Ethernet → IP → TCP/UDP/ICMP → DNS/HTTP** |
| **TCP Intelligence** | Statless logging | **Full RFC 793 State Machine** per flow |
| **DNS Attribution** | Raw hex dump | **Recursive DNS Label Parsing** (with compression) |
| **Protocol Discovery** | Port-based guess | **Payload-Content Inspection** (any port) |
| **Security Logic** | None | **Live ARP Spoofing & Port Scan Alerts** |
| **Data Export** | Text only | **PCAP (libpcap) Format** for Wireshark analysis |
| **Architecture** | High-level libs | **Zero-Dependency**: Pure Python `socket.AF_PACKET` |

## Usage

```bash
# Live Capture: Basic traffic monitoring on eth0
sudo python3 sniffer.py

# Focused Forensic: Filter for specific host/port combinations
sudo python3 sniffer.py --filter "host 192.168.100.10 and port 8080"

# Intelligence Gathering: DNS-only capture with PCAP export
sudo python3 sniffer.py --filter "dns" --pcap investigation.pcap

# IDS Mode: Alert on aggressive port scanning (threshold: 20 ports / 5s)
sudo python3 sniffer.py --scan-threshold 20

# Payload Analysis: Real-time HEX/ASCII dump + 5s metrics
sudo python3 sniffer.py --payload --stats-interval 5
```

## Sample Output

```text
  sniffer.py — capturing on eth0  filter='tcp and port 8080'

  TIME           PROTO  SRC                      DST                      INFO
  ─────────────  ─────  ───────────────────────  ───────────────────────  ───────────────────────────────────
  10:32:01.123   TCP    192.168.100.10:45678     192.168.100.30:8080      [SYN] win=64240
  10:32:01.125   TCP    192.168.100.30:8080      192.168.100.10:45678     [SYN+ACK] win=65535

  ► EST  192.168.100.10:45678 → 192.168.100.30:8080  [ESTABLISHED]

  10:32:01.127   HTTP   192.168.100.10:45678     192.168.100.30:8080      GET /shell.sh
  10:32:01.130   HTTP   192.168.100.30:8080      192.168.100.10:45678     200 OK

  ► [!] PORT SCAN ALERT: 192.168.100.10 probed 23 ports in 5s window

  STATS │ pkts=1847  bytes=312KB  rate=183 pkt/s  1.2 KB/s  │ TCP:71%  UDP:18%  DNS:8%  ARP:3%
  Top talkers: 192.168.100.10:892  192.168.100.30:634
```

## Engineering & Design Decisions

- **Kernel-Direct Raw Sockets**: Uses `socket.AF_PACKET` to bypass the standard transport layer, allowing the engine to see every byte of the Ethernet frame, including headers usually stripped by the OS.
- **Binary Deserialization**: Employs `struct.unpack` with precise format strings to parse binary headers. For example, TCP bitmasks are handled manually to extract data-offsets and control flags (SYN, ACK, PSH) accurately.
- **Robust DNS Parsing**: Implements a recursive DNS label resolver that correctly follows compression pointers (0xC0 prefix), including loop-detection to prevent malicious infinite pointer traps.
- **Bi-Endian PCAP Generation**: Writes the global PCAP header using native byte-ordering, ensuring full compatibility with binary analysis tools like Wireshark and `tcpdump`.
- **Concurrent Analysis Threads**: Separates the high-speed capture loop from the state analysis and UI reporting threads via thread-safe shared state (locked `dict` objects), preventing UI rendering from dropping packets.

