# Project 04 — Packet Sniffer

**Deep-packet inspection sniffer built on raw sockets — no Scapy, no libpcap, no third-party libraries.**

## What makes this different

A basic sniffer reads raw bytes and prints source/dest IPs. This one fully decodes every protocol layer, runs stateful analysis engines on top of the decoded data, and writes Wireshark-compatible output — all in pure Python stdlib.

| Feature | Basic sniffer | This sniffer |
|---------|--------------|--------------|
| Protocol parsing | IP header only | Ethernet → IP → TCP/UDP/ICMP → DNS/HTTP |
| TCP state tracking | None | Full RFC 793 state machine per 4-tuple |
| DNS intelligence | None | Binary DNS question/answer parsing (with compression) |
| HTTP detection | Port-based guess | Payload-content inspection, any port |
| ARP spoofing | None | Real-time IP→MAC change detection |
| Port scan detection | None | Sliding-window counter, configurable threshold |
| PCAP output | None | Wireshark-compatible binary PCAP (libpcap format) |
| Filtering | None | BPF-like: `tcp and port 80`, `host 1.2.3.4`, `dns` |
| Stats | None | Live dashboard: pkt/s, KB/s, protocol breakdown, top talkers |

## Usage

```bash
# Basic capture on eth0
sudo python3 sniffer.py

# Filter to specific host + port
sudo python3 sniffer.py --filter "host 192.168.100.10 and port 8080"

# DNS traffic only, save to PCAP
sudo python3 sniffer.py --filter "dns" --pcap dns_capture.pcap

# Watch for port scans (alert at 20 unique ports in 5s)
sudo python3 sniffer.py --scan-threshold 20

# Show TCP payload content + stats every 5s
sudo python3 sniffer.py --payload --stats-interval 5
```

## Sample output

```
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

## Key design decisions

- **Pure stdlib** — `socket.AF_PACKET` + `struct.unpack` only. Understanding the binary layout of every header is the whole point of building this from scratch.
- **`struct.unpack` format strings are exact** — e.g. TCP uses `!HHLLBBHHH` where the `BB` bytes are the data-offset/NS nibble and the flags byte, so TCP options are correctly skipped via `(data_offset_byte >> 4) * 4`
- **DNS label compression** — the `_parse_dns_name()` function follows compression pointers (0xC0 prefix) and tracks visited offsets to prevent pointer-loop infinite loops
- **PCAP format** — the global header uses `=` (native byte order) to match what `tcpdump` writes; per-packet headers prepend `ts_sec + ts_usec + incl_len + orig_len`
- **Thread safety** — all analyzer classes (`ConnectionTracker`, `ARPWatcher`, `PortScanDetector`) protect their internal state with `threading.Lock()` so the stats background thread never races with the capture thread
