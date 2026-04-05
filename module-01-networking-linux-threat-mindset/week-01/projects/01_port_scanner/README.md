# Project 01 — Professional TCP Port Scanner

**Author: Kuldeep Singh**

---

**High-performance, multi-threaded TCP port scanner with protocol-aware banner grabbing, version extraction, and structured JSON export.**

## Security Researcher Perspective

In modern offensive security, a basic "is the port open?" check is insufficient. This tool is designed to mimic the reconnaissance phase of a sophisticated actor, focusing on **Service Fingerprinting** and **Protocol Identification** to build an accurate attack surface map.

## Technical Differentiators

| Feature | Standard Scanner | This Scanner |
|---------|--------------|--------------|
| **Probing Logic** | Generic HTTP HEAD | **Per-protocol handshakes** (SSH, FTP, SMTP, MySQL, etc.) |
| **Port Specification** | Continuous range only | Flexible: `top100`, list (`22,80`), or complex ranges |
| **Metadata Extraction** | Raw banner dump | **Regex-parsed clean version strings** |
| **Performance** | Synchronous/Single-threaded | **Highly concurrent** via `queue`-based thread pooling |
| **Operational Security** | Noisy, predictable | Configurable retries and timeouts for jitter evasion |

## Usage

```bash
# Reconnaissance: Scan default range 1-1024
python3 port_scanner.py 192.168.100.30

# Full Attribution: 65k scan with high concurrency
python3 port_scanner.py 192.168.100.30 -p 1-65535 --threads 200

# Automated Workflow: Targeted scan with JSON export
python3 port_scanner.py 192.168.100.30 -p 22,80,443,3306,8080-8090 --json out.json

# Speed Recon: Top 100 most common services
python3 port_scanner.py 192.168.100.30 -p top100
```

## Sample Output

```text
  port_scanner.py  |  target: 192.168.100.30
  ports: 1-1024 (1024 total)  |  threads: 150  |  timeout: 0.5s

  [========================================] 1024/1024

  Scan report for 192.168.100.30
  Elapsed : 4.2s  |  Rate : 243.8 ports/sec  |  Probed : 1024

  PORT     SERVICE        LATENCY    VERSION / BANNER
  -------  -------------  ---------  --------------------------------------------------
  22/tcp   ssh              1.2 ms   8.9p1 Ubuntu-3ubuntu0.6
  80/tcp   http             0.8 ms   Apache/2.4.54 (Ubuntu)
  3306/tcp mysql            1.1 ms   8.0.32-MySQL Community Server
  8080/tcp http-alt         0.9 ms   SimpleHTTP/0.6 Python/3.10.12

  4 open port(s) found out of 1024 probed.
```

## Engineering & Design Decisions

- **Low-Level Socket Optimization**: Utilizes `socket.connect_ex()` to handle connection results via error codes, pathologically reducing exception overhead during mass scans.
- **Thread Safety**: Implements `queue.Queue` for thread-safe work distribution, ensuring zero-collision port processing without manual locking.
- **Resource Reuse**: Banner grabbing is performed on the existing open socket, avoiding redundant TCP handshakes and minimizing network noise.
- **Data Portability**: Leverages `dataclasses` for internal state, enabling direct serialization to JSON for integration with downstream analysis tools (e.g., SIEM, Vulnerability Scanners).
- **Zero-Wait Progress Monitoring**: The progress bar is managed on the main thread via liveness polling, ensuring accurate real-time feedback without thread starvation.

