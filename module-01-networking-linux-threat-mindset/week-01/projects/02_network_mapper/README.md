# Project 02 — Network Mapper

**Subnet-wide host discovery with dual-mode detection, TTL-based OS fingerprinting, ARP MAC lookup, and per-host port scanning.**

## What makes this different

A basic mapper does a ping sweep and calls it done — it misses any host that blocks ICMP (most cloud VMs, hardened servers, and firewalled containers do). This mapper adds a **TCP fallback** and then layers on OS fingerprinting and MAC resolution without sending a single extra packet.

| Feature | Basic mapper | This mapper |
|---------|-------------|-------------|
| Discovery | ICMP ping only | ICMP ping → TCP fallback (ports 80, 443, 22) |
| OS detection | None | TTL analysis → Linux/macOS · Windows · Cisco |
| MAC address | None | ARP cache read (zero extra traffic) |
| Hostname | None | Reverse DNS per live host |
| Port output | Port numbers | Port number + service name label |
| Concurrency | Sequential per host | All hosts probed in parallel |
| Output | Print only | Live per-host output + summary table + JSON |

## Usage

```bash
# Scan default lab network
python3 net_mapper.py 192.168.100.0/24

# Different subnet with custom ports + JSON
python3 net_mapper.py 10.0.0.0/24 -p 22,80,443,3306 --json report.json

# Tune threads and timeout
python3 net_mapper.py 192.168.100.0/24 --threads 50 --timeout 1.0
```

## Sample output

```
  net_mapper.py  |  network: 192.168.100.0/24
  threads: 100  |  timeout: 0.5s  |  ports/host: 20

  [1/2] Host Discovery — 192.168.100.0/24  (254 addresses)
        Strategy: ICMP ping → TCP fallback (80, 443, 22)

  UP  192.168.100.1    (router.lab)  MAC: AA:BB:CC:DD:EE:01
       OS hint : Cisco / Network device  TTL=255  0.4ms
       Open    : 22/ssh  80/http

  UP  192.168.100.30   (webserver.lab)  MAC: AA:BB:CC:DD:EE:30
       OS hint : Linux / macOS  TTL=64  0.6ms
       Open    : 22/ssh  80/http  3306/mysql  8080/http-alt

  ────────────────────────────────────────
  SUMMARY — 192.168.100.0/24
  Hosts probed : 254
  Hosts up     : 2
  Elapsed      : 8.3s
```

## Key design decisions

- Two-stage discovery catches ICMP-blocking hosts that a pure ping sweep misses
- ARP cache is read **once** before threads start — shared across all workers, zero extra ARP traffic
- TTL ranges have tolerant bounds (`range(1, 65)` for Linux) to handle multi-hop paths that decrement TTL
- `threading.Semaphore` caps concurrency so we don't flood small LANs
- Per-host port scan runs inside the discovery thread — no second pass over live hosts
