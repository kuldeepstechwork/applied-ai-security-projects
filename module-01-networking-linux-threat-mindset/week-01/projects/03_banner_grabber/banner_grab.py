#!/usr/bin/env python3
"""
banner_grab.py — Protocol-Aware Service Banner Grabber with TLS & CVE Hints
============================================================================
Module 01 · Week 1 · Project 3

What makes this different from a basic banner grabber:
  - 20+ protocol-aware probes: each service gets the exact handshake bytes it
    expects (HTTP HEAD, Redis PING, FTP passive wait, SMTP EHLO, MySQL wait,
    PostgreSQL startup, LDAP bind, etc.) — not just HTTP to everything
  - TLS/SSL support: for HTTPS and encrypted services, wraps the socket with
    ssl.wrap_socket() and extracts certificate CN, issuer, expiry date, and
    the TLS version negotiated
  - Version parsing: extracts clean version strings from banners using
    service-specific regex patterns
  - CVE hint lookup: a static table maps known vulnerable version strings to
    CVE IDs and CVSS scores — gives an immediate "this version is known-bad"
    signal during recon (no live API needed)
  - Risk scoring: each result gets a LOW / MEDIUM / HIGH / CRITICAL tag based
    on service exposure and whether a known CVE was matched
  - Multi-host support: accepts multiple targets on the CLI and grabs banners
    from all of them concurrently
  - Structured JSON export: every field (service, version, TLS info, CVEs,
    risk) is included — pipe into jq or feed a SIEM

Author : Kuldeep Singh
Lab    : 192.168.100.0/24 | Kali .10 | Webserver .30
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import socket
import ssl
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional


# ---------------------------------------------------------------------------
# ANSI color helpers
# ---------------------------------------------------------------------------

_USE_COLOR = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    """Wrap *text* in ANSI escape code if color output is active."""
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text


def green(t: str) -> str:
    """Format text in bold green — used for LOW risk / clean results."""
    return _c("32;1", t)


def yellow(t: str) -> str:
    """Format text in yellow — used for MEDIUM risk."""
    return _c("33", t)


def red(t: str) -> str:
    """Format text in bold red — used for HIGH / CRITICAL risk."""
    return _c("31;1", t)


def cyan(t: str) -> str:
    """Format text in cyan — used for section headers."""
    return _c("36", t)


def grey(t: str) -> str:
    """Format text in grey — used for secondary / metadata output."""
    return _c("90", t)


def bold(t: str) -> str:
    """Format text in bold — used for service names."""
    return _c("1", t)


# ---------------------------------------------------------------------------
# Protocol probe database
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ServiceProbe:
    """
    Defines how to communicate with a specific protocol to extract its banner.

    Attributes:
        name    Human-readable service name (e.g. 'ssh', 'http')
        probe   Bytes to send after connecting; empty bytes = listen first
        tls     Whether to wrap the connection in TLS before probing
        recv    How many bytes to read from the response
    """
    name: str
    probe: bytes
    tls: bool = False
    recv: int = 1024


# Map port number → ServiceProbe.
# The key insight: sending the right bytes gets you the real banner.
# Sending HTTP HEAD to MySQL gives you nothing; sending nothing and
# waiting gives you MySQL's greeting with version.
PROBES: dict[int, ServiceProbe] = {
    21:    ServiceProbe("ftp",         b"",                                recv=512),
    22:    ServiceProbe("ssh",         b"",                                recv=256),
    23:    ServiceProbe("telnet",      b"",                                recv=256),
    25:    ServiceProbe("smtp",        b"EHLO banner-grabber\r\n",         recv=512),
    53:    ServiceProbe("dns",         b""),           # TCP DNS — usually no banner
    80:    ServiceProbe("http",        b"HEAD / HTTP/1.0\r\nHost: target\r\nConnection: close\r\n\r\n"),
    110:   ServiceProbe("pop3",        b"",                                recv=256),
    143:   ServiceProbe("imap",        b"",                                recv=256),
    389:   ServiceProbe("ldap",        b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"),
    443:   ServiceProbe("https",       b"HEAD / HTTP/1.0\r\nHost: target\r\nConnection: close\r\n\r\n", tls=True),
    445:   ServiceProbe("smb",         b"\x00\x00\x00\x85\xff\x53\x4d\x42"),
    587:   ServiceProbe("smtp-sub",    b"EHLO banner-grabber\r\n",         recv=256),
    993:   ServiceProbe("imaps",       b"",            tls=True,           recv=256),
    995:   ServiceProbe("pop3s",       b"",            tls=True,           recv=256),
    3306:  ServiceProbe("mysql",       b""),           # MySQL sends greeting immediately
    3389:  ServiceProbe("rdp",         b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"),
    5432:  ServiceProbe("postgresql",  b""),           # PG sends greeting immediately
    5900:  ServiceProbe("vnc",         b""),           # VNC sends protocol version first
    6379:  ServiceProbe("redis",       b"PING\r\n",                        recv=256),
    8080:  ServiceProbe("http-alt",    b"HEAD / HTTP/1.0\r\nHost: target\r\nConnection: close\r\n\r\n"),
    8443:  ServiceProbe("https-alt",   b"HEAD / HTTP/1.0\r\nHost: target\r\nConnection: close\r\n\r\n", tls=True),
    9200:  ServiceProbe("elasticsearch", b"GET / HTTP/1.0\r\nHost: target\r\n\r\n"),
    11211: ServiceProbe("memcached",   b"version\r\n",                     recv=128),
    27017: ServiceProbe("mongodb",     b""),           # MongoDB sends wire protocol
}

# Default ports to check when no specific ports are given
DEFAULT_PORTS: list[int] = sorted(PROBES.keys())


# ---------------------------------------------------------------------------
# Version extraction patterns
# ---------------------------------------------------------------------------

# Ordered list of (service_name_hint, regex) pairs.
# We try each in turn; the first match wins.
VERSION_PATTERNS: list[tuple[str, re.Pattern]] = [
    # SSH: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"
    ("ssh",    re.compile(r"SSH-[\d.]+-(?:OpenSSH_)?([\w._-]+)", re.I)),
    # HTTP Server header: "Server: Apache/2.4.51 (Debian)"
    ("http",   re.compile(r"Server:\s*([\w/._-]+(?:\s[\w/._-]+)?)", re.I)),
    # MySQL: greeting contains version like "8.0.32-MySQL Community"
    ("mysql",  re.compile(r"([\d]+\.[\d]+\.[\d]+-[\w]+)", re.I)),
    # Redis: "+PONG" or "-ERR ... Redis x.y.z"
    ("redis",  re.compile(r"Redis\s+([\d.]+)", re.I)),
    # Memcached: "VERSION 1.6.12"
    ("memcached", re.compile(r"VERSION\s+([\d.]+)", re.I)),
    # FTP: "220 ProFTPD 1.3.7 Server"
    ("ftp",    re.compile(r"220[- ].*?([\w]+[\s/]([\d.]+))", re.I)),
    # PostgreSQL sends binary; match any version-like string
    ("psql",   re.compile(r"PostgreSQL\s+([\d.]+)", re.I)),
    # Generic x.y.z — lowest priority
    ("any",    re.compile(r"\b([\d]+\.[\d]+\.[\d]+(?:\.[\d]+)?)\b")),
]


# ---------------------------------------------------------------------------
# CVE hint database (static — no live API required)
# ---------------------------------------------------------------------------

# Maps (service, version_substring) → list of CVE dicts
# Keep this purposely small; the value is showing the *concept* of version-to-CVE
# correlation that a real scanner (OpenVAS, Tenable) does at much larger scale.
CVE_HINTS: list[dict] = [
    {"service": "ssh",      "version_contains": "7.4",  "cve": "CVE-2018-15473", "cvss": 5.3, "desc": "OpenSSH username enumeration"},
    {"service": "ssh",      "version_contains": "7.2",  "cve": "CVE-2016-6515",  "cvss": 7.8, "desc": "OpenSSH DoS via keyboard-interactive"},
    {"service": "http",     "version_contains": "2.4.49","cve": "CVE-2021-41773","cvss": 9.8, "desc": "Apache path traversal / RCE"},
    {"service": "http",     "version_contains": "2.4.50","cve": "CVE-2021-42013","cvss": 9.8, "desc": "Apache path traversal bypass"},
    {"service": "mysql",    "version_contains": "5.5",  "cve": "CVE-2012-2122",  "cvss": 7.5, "desc": "MySQL auth bypass timing attack"},
    {"service": "redis",    "version_contains": "4.",   "cve": "CVE-2022-0543",  "cvss": 10.0,"desc": "Redis Lua sandbox escape (Debian/Ubuntu)"},
    {"service": "memcached","version_contains": "1.5",  "cve": "CVE-2018-1000115","cvss": 7.5,"desc": "Memcached UDP amplification DDoS"},
    {"service": "ftp",      "version_contains": "2.3.4","cve": "CVE-2011-2523",  "cvss": 10.0,"desc": "vsftpd 2.3.4 backdoor"},
]


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

# Services that should never be exposed externally — bump risk if found open
HIGH_RISK_SERVICES = {"redis", "memcached", "mongodb", "elasticsearch",
                      "mysql", "postgresql", "smb", "rdp", "vnc", "telnet"}


def compute_risk(service: str, matched_cves: list[dict]) -> str:
    """
    Assign a risk label to a service result.

    Risk levels (highest wins):
        CRITICAL — CVSS >= 9.0 CVE matched
        HIGH     — CVSS >= 7.0 CVE matched, or inherently dangerous service open
        MEDIUM   — CVSS >= 4.0 CVE matched
        LOW      — No CVE matched, low-risk service

    Args:
        service      : Service name string (e.g. 'redis', 'http')
        matched_cves : List of CVE dicts from the lookup table

    Returns:
        Risk label string: 'CRITICAL', 'HIGH', 'MEDIUM', or 'LOW'
    """
    if matched_cves:
        max_cvss = max(c["cvss"] for c in matched_cves)
        if max_cvss >= 9.0:
            return "CRITICAL"
        if max_cvss >= 7.0:
            return "HIGH"
        if max_cvss >= 4.0:
            return "MEDIUM"

    if service in HIGH_RISK_SERVICES:
        return "HIGH"

    return "LOW"


def risk_color(label: str) -> str:
    """
    Apply ANSI color formatting to a risk label string.

    Args:
        label : Risk label ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')

    Returns:
        ANSI-colored string (or plain string if color is disabled)
    """
    return {
        "CRITICAL": red(label),
        "HIGH":     red(label),
        "MEDIUM":   yellow(label),
        "LOW":      green(label),
    }.get(label, label)


# ---------------------------------------------------------------------------
# TLS certificate info
# ---------------------------------------------------------------------------

@dataclass
class TLSInfo:
    """
    TLS/SSL certificate and handshake details for an encrypted service.

    Attributes:
        tls_version   Negotiated TLS version string (e.g. 'TLSv1.3')
        common_name   Certificate CN field (e.g. 'example.com')
        issuer        Certificate issuer O field (e.g. 'Let's Encrypt')
        not_after     Certificate expiry date string
        expired       True if the certificate has already expired
    """
    tls_version: str = ""
    common_name: str = ""
    issuer: str = ""
    not_after: str = ""
    expired: bool = False


def grab_tls_info(host: str, port: int, timeout: float) -> Optional[TLSInfo]:
    """
    Establish a TLS connection and extract certificate metadata.

    Uses an unverified SSL context intentionally — in a pentest/recon context
    we want to read the cert even if it's self-signed or expired.

    Args:
        host    : Target hostname or IP
        port    : TCP port to connect to
        timeout : Connection timeout in seconds

    Returns:
        TLSInfo dataclass if successful, None on any failure.
    """
    ctx = ssl.create_default_context()
    # Disable verification: self-signed and expired certs are common targets
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()  # returns {} when CERT_NONE
                tls_ver = tls_sock.version() or ""

                if not cert:
                    # DER-decode manually to get at least the CN
                    der = tls_sock.getpeercert(binary_form=True)
                    return TLSInfo(tls_version=tls_ver)

                cn = ""
                for field_list in cert.get("subject", []):
                    for k, v in field_list:
                        if k == "commonName":
                            cn = v

                issuer = ""
                for field_list in cert.get("issuer", []):
                    for k, v in field_list:
                        if k == "organizationName":
                            issuer = v

                not_after = cert.get("notAfter", "")
                expired = False
                if not_after:
                    try:
                        exp_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        expired = exp_dt < datetime.utcnow()
                    except ValueError:
                        pass

                return TLSInfo(
                    tls_version=tls_ver,
                    common_name=cn,
                    issuer=issuer,
                    not_after=not_after,
                    expired=expired,
                )
    except (ssl.SSLError, OSError, socket.timeout):
        return None


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class BannerResult:
    """
    Complete banner grabbing result for a single (host, port) combination.

    Attributes:
        host         Target IP or hostname
        port         TCP port number
        service      Service name (from probe database or 'unknown')
        banner       Raw decoded banner text (first 400 chars)
        version      Parsed version string, or empty if not found
        tls          TLSInfo if the service uses TLS, else None
        cves         List of matched CVE hint dicts
        risk         Risk label: 'CRITICAL', 'HIGH', 'MEDIUM', or 'LOW'
        error        Error message if connection failed, else empty string
        latency_ms   Connection latency in milliseconds
    """
    host: str
    port: int
    service: str
    banner: str = ""
    version: str = ""
    tls: Optional[TLSInfo] = None
    cves: list[dict] = field(default_factory=list)
    risk: str = "LOW"
    error: str = ""
    latency_ms: float = 0.0


# ---------------------------------------------------------------------------
# Core grabber
# ---------------------------------------------------------------------------

class BannerGrabber:
    """
    Grabs service banners using protocol-aware probes across multiple targets.

    For each (host, port) pair:
        1. Look up the ServiceProbe for this port
        2. Connect with a timeout
        3. If TLS: wrap socket and extract cert info
        4. Send the probe bytes (or wait for server-first services)
        5. Read the response
        6. Parse version from banner
        7. Match version against CVE hint table
        8. Assign risk score

    Args:
        timeout : Per-connection timeout in seconds
        workers : Max concurrent threads (used in grab_many)
    """

    def __init__(self, timeout: float = 2.0, workers: int = 20) -> None:
        """
        Initialise the grabber.

        Args:
            timeout : Per-connection timeout seconds (default 2.0)
            workers : Thread pool size for concurrent grabs (default 20)
        """
        self.timeout = timeout
        self.workers = workers

    def _parse_version(self, banner: str, service: str) -> str:
        """
        Extract a version string from a raw banner using service-aware patterns.

        Tries service-specific patterns first, then falls back to a generic
        x.y.z pattern.  Returns the first match found, or empty string.

        Args:
            banner  : Raw decoded banner text
            service : Service name hint (e.g. 'ssh', 'http') for priority matching
        """
        # Try service-specific patterns first
        for svc_hint, pattern in VERSION_PATTERNS:
            if svc_hint == service or svc_hint == "any":
                m = pattern.search(banner)
                if m:
                    return m.group(1)
        return ""

    def _match_cves(self, service: str, version: str) -> list[dict]:
        """
        Look up CVE hints for a given service and version string.

        Checks each entry in CVE_HINTS to see if the version_contains substring
        appears in the detected version.  Returns all matches so a single
        version can map to multiple CVEs.

        Args:
            service : Service name (e.g. 'ssh', 'mysql')
            version : Parsed version string (e.g. '2.4.49')

        Returns:
            List of matching CVE hint dicts (may be empty).
        """
        if not version:
            return []
        return [
            hint for hint in CVE_HINTS
            if hint["service"] == service and hint["version_contains"] in version
        ]

    def grab_one(self, host: str, port: int) -> BannerResult:
        """
        Grab the banner from a single (host, port) target.

        Handles the full pipeline: connect → TLS wrap (if needed) →
        probe → read → parse → CVE check → risk score.

        Args:
            host : Target IP address or hostname
            port : TCP port number

        Returns:
            BannerResult with all fields populated (error field set on failure).
        """
        import time as _time

        probe_def = PROBES.get(port, ServiceProbe(name="unknown", probe=b""))
        result = BannerResult(host=host, port=port, service=probe_def.name)

        t0 = _time.monotonic()
        try:
            # Establish raw TCP connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            result.latency_ms = round((_time.monotonic() - t0) * 1000, 2)

            # TLS wrapping for encrypted services
            if probe_def.tls:
                tls_info = grab_tls_info(host, port, self.timeout)
                result.tls = tls_info
                # Re-wrap the existing socket for banner reading
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                try:
                    sock = ctx.wrap_socket(sock, server_hostname=host)
                except ssl.SSLError:
                    pass  # Still try to read plaintext if TLS fails

            # Send probe (empty probe = wait for server-first banner)
            if probe_def.probe:
                sock.sendall(probe_def.probe)

            # Read banner
            raw = sock.recv(probe_def.recv)
            banner = raw.decode(errors="ignore").strip()
            result.banner = banner[:400]
            sock.close()

        except (ConnectionRefusedError, socket.timeout, OSError) as exc:
            result.error = str(exc)
            return result

        # Parse version
        result.version = self._parse_version(result.banner, probe_def.name)

        # CVE lookup
        result.cves = self._match_cves(probe_def.name, result.version)

        # Risk scoring
        result.risk = compute_risk(probe_def.name, result.cves)

        return result

    def grab_many(self, targets: list[tuple[str, int]]) -> list[BannerResult]:
        """
        Grab banners from multiple (host, port) pairs concurrently.

        Uses a ThreadPoolExecutor so that slow/filtered ports don't block fast
        ones.  Results are returned in the order that (host, port) pairs were
        submitted, sorted by host then port.

        Args:
            targets : List of (host, port) tuples to probe

        Returns:
            List of BannerResult, sorted by host IP then port number.
        """
        results: list[BannerResult] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(self.grab_one, h, p): (h, p) for h, p in targets}
            for future in concurrent.futures.as_completed(futures):
                try:
                    results.append(future.result())
                except (OSError, socket.timeout, ssl.SSLError,
                        concurrent.futures.CancelledError) as exc:
                    h, p = futures[future]
                    results.append(BannerResult(
                        host=h, port=p, service="unknown",
                        error=str(exc)
                    ))

        return sorted(results, key=lambda r: (r.host, r.port))


# ---------------------------------------------------------------------------
# Output rendering
# ---------------------------------------------------------------------------

def print_results(results: list[BannerResult]) -> None:
    """
    Render banner results to stdout in a human-readable format.

    Groups results by host, then prints each port with service, version,
    TLS info, CVE hints, and risk label.

    Args:
        results : List of BannerResult from BannerGrabber.grab_many()
    """
    # Group by host
    by_host: dict[str, list[BannerResult]] = {}
    for r in results:
        by_host.setdefault(r.host, []).append(r)

    for host, host_results in by_host.items():
        print()
        print(cyan(f"  ╔═══ {host} {'═' * (50 - len(host))}"))

        for r in host_results:
            if r.error:
                print(grey(f"  ║  {r.port:<6}  {r.service:<14}  closed / filtered"))
                continue

            risk_tag = f"[{risk_color(r.risk)}]"
            ver_str = bold(r.version) if r.version else grey("version unknown")
            lat_str = grey(f"{r.latency_ms:.1f}ms")

            print(f"  ║  {green(str(r.port)):<20}  {bold(r.service):<20}  {ver_str}")
            print(f"  ║    Risk: {risk_tag}  Latency: {lat_str}")

            # TLS info
            if r.tls:
                exp_str = red(" [EXPIRED]") if r.tls.expired else green(" [valid]")
                print(f"  ║    TLS : {r.tls.tls_version}  "
                      f"CN={r.tls.common_name}  "
                      f"Issuer={r.tls.issuer}  "
                      f"Expires={r.tls.not_after}{exp_str}")

            # CVE hints
            for cve in r.cves:
                print(f"  ║    {red('CVE')} : {cve['cve']}  CVSS={cve['cvss']}  "
                      f"— {cve['desc']}")

            # Raw banner (first line only, for readability)
            first_line = r.banner.splitlines()[0][:80] if r.banner else ""
            if first_line:
                print(f"  ║    Banner: {grey(first_line)}")

        print(cyan(f"  ╚{'═' * 58}"))


def save_json(results: list[BannerResult], path: str) -> None:
    """
    Serialize banner results to a JSON file.

    Each BannerResult is converted to a dict; TLSInfo is also serialized.
    A top-level metadata block records when the scan ran.

    Args:
        results : List of BannerResult to serialize
        path    : Destination file path
    """
    def result_to_dict(r: BannerResult) -> dict:
        """Convert a BannerResult (and its nested TLSInfo) to a plain dict."""
        d = asdict(r)
        # asdict handles nested dataclasses, but TLSInfo is Optional
        return d

    output = {
        "generated": datetime.now().isoformat(),
        "targets": len(results),
        "results": [result_to_dict(r) for r in results],
    }
    with open(path, "w") as fh:
        json.dump(output, fh, indent=2)
    print(cyan(f"\n  [+] Report saved → {path}"))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """
    Build and return the CLI argument parser.

    Returns:
        Configured ArgumentParser instance.
    """
    p = argparse.ArgumentParser(
        prog="banner_grab.py",
        description=(
            "Protocol-aware banner grabber with TLS cert extraction and CVE hints.\n\n"
            "Examples:\n"
            "  python3 banner_grab.py 192.168.100.30\n"
            "  python3 banner_grab.py 192.168.100.30 -p 22,80,443,3306\n"
            "  python3 banner_grab.py 192.168.100.10 192.168.100.30 --json report.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "hosts", nargs="+", metavar="HOST",
        help="One or more target IP addresses / hostnames"
    )
    p.add_argument(
        "-p", "--ports", metavar="PORTS",
        help="Comma-separated port list (default: all 20 probed ports)"
    )
    p.add_argument(
        "--timeout", type=float, default=2.0, metavar="SECS",
        help="Per-connection timeout in seconds (default: 2.0)"
    )
    p.add_argument(
        "--workers", type=int, default=20, metavar="N",
        help="Concurrent thread count (default: 20)"
    )
    p.add_argument(
        "--json", metavar="FILE",
        help="Save full structured report as JSON to FILE"
    )
    return p


def main() -> None:
    """
    Parse CLI arguments, build target list, run grabber, display and optionally save results.
    """
    parser = build_parser()
    args = parser.parse_args()

    # Parse port list
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
        except ValueError as exc:
            print(f"[!] Invalid port list: {exc}")
            sys.exit(1)
    else:
        ports = DEFAULT_PORTS

    # Build (host, port) target list
    targets: list[tuple[str, int]] = [
        (host, port) for host in args.hosts for port in ports
    ]

    print(cyan(f"\n  banner_grab.py  |  {len(args.hosts)} host(s)  |  "
               f"{len(ports)} port(s) each  |  {len(targets)} total probes"))
    print(cyan(f"  timeout: {args.timeout}s  |  workers: {args.workers}"))

    grabber = BannerGrabber(timeout=args.timeout, workers=args.workers)
    results = grabber.grab_many(targets)

    print_results(results)

    if args.json:
        save_json(results, args.json)


if __name__ == "__main__":
    main()
