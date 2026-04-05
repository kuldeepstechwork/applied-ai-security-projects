# Project 02 — Professional Network Mapper

**Author: Kuldeep Singh**

---

**Subnet-wide host discovery engine with dual-mode detection, TTL-based OS fingerprinting, ARP MAC resolution, and per-host service auditing.**

## Security Researcher Perspective

Standard "ping sweeps" are trivial to defeat with basic firewall rules. This tool implements a **Defense-Aware Discovery** strategy, layering ICMP probing with TCP fallback to identify "stealth" hosts that reject ICMP but expose common services (HTTP, SSH, etc.). It prioritizes passive information gathering (TTL analysis, ARP cache) to minimize the tool's network footprint.

## Technical Differentiators

| Feature | Standard Mapper | This Mapper |
|---------|-------------|-------------|
| **Discovery Logic** | ICMP Echo only | **ICMP → TCP Fallback** (80, 443, 22) |
| **OS Attribution** | None | **TTL Signature Analysis** (Linux, Win, Cisco) |
| **Layer 2 Mapping** | None | **Active ARP Cache Integration** |
| **Service Labeling** | Port numbers only | **Port + Dynamic Service Resolution** |
| **Execution Model** | Sequential | **Thread-pooled parallel discovery** |
| **Operational Impact** | Low visibility | **OPSEC-focused**: Passive MAC resolution |

## Usage

```bash
# Discovery: Scan internal lab network
python3 net_mapper.py 192.168.100.0/24

# Asset Inventory: Custom ports + Structured JSON export
python3 net_mapper.py 10.0.0.0/24 -p 22,80,443,3306 --json inventory.json

# High Performance: Optimized concurrency for large subnets
python3 net_mapper.py 172.16.0.0/24 --threads 100 --timeout 1.0
```

## Sample Output

```text
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

  ──────────────────────────────────────────────────────────
  SUMMARY — 192.168.100.0/24
  Hosts probed : 254
  Hosts up     : 2
  Elapsed      : 8.3s
```

## Engineering & Design Decisions

- **Multi-Vector Discovery**: Prevents "blind spots" by falling back to TCP service checks if a host suppresses ICMP Echo replies.
- **Zero-Packet MAC Resolution**: Leverages the system's ARP table to associate hardware addresses with discovered IPs, avoiding redundant Layer 2 broadcasts.
- **Probabilistic OS Fingerprinting**: Analyzes Time-to-Live (TTL) values from response packets to infer the target operating system stack without intensive fingerprinting scripts.
- **Resource Management**: Implements `threading.Semaphore` to cap active network connections, preventing socket exhaustion on the host or accidental DoS on fragile network segments.
- **Unified Pipeline**: Performs discovery, OS inference, and service enumeration in a single pass per host, significantly reducing the total time-to-results.

