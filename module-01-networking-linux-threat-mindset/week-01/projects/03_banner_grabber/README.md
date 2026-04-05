# Project 03 — Professional Service Banner Grabber

**Author: Kuldeep Singh**

---

**Protocol-aware service fingerprinter with TLS certificate extraction, regex-based version parsing, and integrated CVE vulnerability mapping.**

## Security Researcher Perspective

Automated vulnerability scanning begins with accurate **Service Identification**. This tool moves beyond generic probes, implementing a **Multi-Protocol Handshake Engine** that speaks the "native tongue" of 20+ common services (MySQL, Redis, SMTP, etc.). It enables researchers to identify not just *that* a port is open, but exactly *what* version is running and its associated risk profile via static CVE mapping.

## Technical Differentiators

| Feature | Standard Grabber | This Grabber |
|---------|--------------|--------------|
| **Probe Strategy** | Generic HTTP HEAD | **Context-Specific Handshakes** (LDAP, SMB, Memcached, etc.) |
| **Encryption Awareness** | Blind socket connection | **Deep TLS Inspection**: CN, Issuer, Expiry, Cipher |
| **Data Extraction** | Raw banner dump | **Regex-Engine Parsing** for clean version strings |
| **Vulnerability Intel** | None | **Offline CVE Mapping** with CVSS scoring |
| **Risk Orchestration** | Manual review | **Heuristic Risk Scoring** (Critical/High/Med/Low) |
| **Concurrency** | Sequential | **Asynchronous Task Dispatch** via `ThreadPoolExecutor` |

## Usage

```bash
# Basic Recon: Grab banners for default service ports
python3 banner_grab.py 192.168.100.30

# Targeted Audit: Specific high-value ports
python3 banner_grab.py 192.168.100.30 -p 22,80,443,3306,6379

# Massive Surface Area: Simultaneous multi-host audit with JSON export
python3 banner_grab.py 192.168.100.10 192.168.100.30 --json full_audit.json

# High Latency Evasion: Extended timeout for unstable targets
python3 banner_grab.py 192.168.100.30 --timeout 4.0
```

## Sample Output

```text
  banner_grab.py  |  2 host(s)  |  5 port(s) each  |  10 total probes

  ╔═══ 192.168.100.30 ═══════════════════════════════════════════════
  ║  22    ssh            8.9p1 Ubuntu-3ubuntu0.6
  ║    Risk: [LOW]  Latency: 1.2ms
  ║    Banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
  ║
  ║  443   https          Apache/2.4.49
  ║    Risk: [CRITICAL]  Latency: 0.9ms
  ║    TLS: TLSv1.3  CN=lab.internal  Expires=Dec 31 2025 [valid]
  ║    CVE: CVE-2021-41773  CVSS=9.8 — Apache path traversal / RCE
  ║    Banner: HTTP/1.1 200 OK Server: Apache/2.4.49
  ╚══════════════════════════════════════════════════════════════════
```

## Engineering & Design Decisions

- **Immutability by Design**: Uses `Frozen Dataclasses` for the `ServiceProbe` database, ensuring thread-safe probe definitions that cannot be modified during execution.
- **Opportunistic TLS Extraction**: Deliberately ignores certificate validation (`ssl.CERT_NONE`) to ensure data extraction from self-signed or expired certificates—common indicators of misconfigured or legacy internal assets.
- **Offline Intelligence**: Features a built-in CVE mapping table, providing immediate security context without external API dependencies or rate-limiting constraints.
- **Non-Blocking Dispatch**: Implements `concurrent.futures.as_completed()`, allowing the engine to process fast-responding targets immediately while waiting for slower sockets, eliminating "head-of-line" blocking.
- **Weighted Risk Heuristics**: Calculates risk scores by prioritizing confirmed CVE vulnerabilities over generic service-type flags, providing a nuanced view of the attack surface.

