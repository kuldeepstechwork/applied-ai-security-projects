# Project 03 — Banner Grabber

**Protocol-aware service fingerprinter with TLS certificate extraction, version parsing, and static CVE hint lookup.**

## What makes this different

Sending `HEAD / HTTP/1.0` to port 3306 gets you nothing from MySQL. Sending it to Redis gets you an error. This grabber ships a **probe database for 20+ protocols** — each service gets the exact bytes it expects. On top of that, it layers TLS certificate inspection and a built-in CVE table so a single run tells you both *what's running* and *whether it's a known-vulnerable version*.

| Feature | Basic grabber | This grabber |
|---------|--------------|--------------|
| Probe strategy | HTTP HEAD everywhere | Per-protocol (HTTP, SSH, FTP, SMTP, MySQL, Redis, Memcached, LDAP…) |
| TLS support | None | TLS wrap → CN, issuer, expiry, expired flag |
| Version extraction | Raw banner dump | Service-specific regex → clean version string |
| CVE hints | None | Static lookup table → CVE ID + CVSS score |
| Risk scoring | None | CRITICAL / HIGH / MEDIUM / LOW per result |
| Multi-host | One at a time | Concurrent across all hosts/ports via thread pool |
| Output | Print only | Colour-coded table + JSON export |

## Usage

```bash
# Grab all 20 default ports on one host
python3 banner_grab.py 192.168.100.30

# Specific ports
python3 banner_grab.py 192.168.100.30 -p 22,80,443,3306,6379

# Multiple hosts simultaneously
python3 banner_grab.py 192.168.100.10 192.168.100.30 --json report.json

# Slower network — increase timeout
python3 banner_grab.py 192.168.100.30 --timeout 4.0
```

## Sample output

```
  banner_grab.py  |  2 host(s)  |  5 port(s) each  |  10 total probes

  ╔═══ 192.168.100.30 ══════════════════════════════
  ║  22    ssh            8.9p1 Ubuntu-3ubuntu0.6
  ║    Risk: [LOW]  Latency: 1.2ms
  ║    Banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
  ║  443   https          Apache/2.4.49
  ║    Risk: [CRITICAL]  Latency: 0.9ms
  ║    TLS: TLSv1.3  CN=lab.internal  Expires=Dec 31 2025 [valid]
  ║    CVE: CVE-2021-41773  CVSS=9.8 — Apache path traversal / RCE
  ║    Banner: HTTP/1.1 200 OK Server: Apache/2.4.49
  ╚══════════════════════════════════════════════════
```

## Key design decisions

- `ServiceProbe` frozen dataclass ensures the probe database is immutable at runtime
- TLS uses `ssl.CERT_NONE` intentionally — self-signed and expired certs are common recon targets
- CVE lookup is **static** (no API key, no rate limit, works offline) — the table is small by design; the architecture scales to thousands of entries
- `concurrent.futures.ThreadPoolExecutor` with `as_completed()` means fast hosts return immediately while slow ones keep running — no head-of-line blocking
- Risk scoring is purely additive: CVE CVSS score wins over service-type heuristic, so a patched Redis scores LOW even though it's in the high-risk service list
