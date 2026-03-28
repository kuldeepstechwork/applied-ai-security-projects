# Project 01 — Port Scanner

**Multi-threaded TCP port scanner with protocol-aware banner grabbing, version extraction, and JSON export.**

## What makes this different

Most basic scanners send an HTTP `HEAD` request to every port — which gets you nothing useful from SSH, MySQL, Redis, or FTP. This scanner maintains a **service probe database**: each port gets the correct handshake bytes for its protocol, so you actually get meaningful banners back.

| Feature | Basic scanner | This scanner |
|---------|--------------|--------------|
| Probes | HTTP HEAD to everything | Per-protocol (HTTP, SSH, FTP, SMTP, MySQL, Redis…) |
| Port syntax | `1-1024` only | `22,80,443` · `1-1024` · `22,80,8000-8090` · `top100` |
| Version info | Raw banner dump | Regex-parsed clean version string |
| Progress | None | Live `[========----] 512/1024` bar |
| Output | Print only | Colour table + optional JSON export |
| Stats | None | Elapsed time · ports/sec · open ratio |
| Retry logic | No | Configurable retries for unstable networks |

## Usage

```bash
# Scan default range 1-1024
python3 port_scanner.py 192.168.100.30

# Full scan with more threads
python3 port_scanner.py 192.168.100.30 -p 1-65535 --threads 200

# Mixed port spec + JSON export
python3 port_scanner.py 192.168.100.30 -p 22,80,443,3306,6379,8080-8090 --json out.json

# Top 100 common ports
python3 port_scanner.py 192.168.100.30 -p top100
```

## Sample output

```
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

## Key design decisions

- `socket.connect_ex()` returns an error code instead of raising — no exception overhead across thousands of ports
- `queue.Queue` distributes ports across threads without index slicing or manual locking on the work list
- Banner grabbing reuses the already-open socket (no second TCP handshake per port)
- `ScanResult` / `ScanReport` dataclasses make results trivially serialisable to JSON
- Progress bar runs on the main thread, polling worker liveness — no extra thread needed
