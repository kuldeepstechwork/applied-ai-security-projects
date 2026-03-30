#!/usr/bin/env python3
"""
port_scanner.py — Professional Multi-threaded TCP Port Scanner
==============================================================
Module 01 · Module 1 · Project 1

What makes this different from a basic scanner:
  - Protocol-aware probes: sends correct handshake bytes per service (HTTP, SSH,
    FTP, SMTP, MySQL, Redis, etc.) instead of blindly sending HTTP to every port
  - Service name resolution: maps port numbers to well-known service names
  - Version extraction: parses banners with regex to pull clean version strings
  - Flexible port syntax: supports ranges ("1-1024"), lists ("22,80,443"),
    and mixed ("22,80,8000-8090") — just like nmap
  - Live progress counter so you know the scan is running
  - Scan statistics: elapsed time, ports/sec, open ratio
  - JSON export for downstream tooling / incident reports
  - Color-coded terminal output (degrades gracefully if no TTY)
  - Retry logic for ports that drop connections under load

Author : Kuldeep Singh
Lab    : 192.168.100.0/24 | Kali .10 | Webserver .30
"""

from __future__ import annotations

import argparse
import json
import queue
import re
import socket
import sys
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional


# ---------------------------------------------------------------------------
# ANSI color helpers — fall back to plain text when not a TTY
# ---------------------------------------------------------------------------

_USE_COLOR = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    """Wrap *text* in an ANSI escape *code* if color output is enabled."""
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text


def green(t: str) -> str:
    """Return text formatted in green (used for OPEN ports)."""
    return _c("32;1", t)


def yellow(t: str) -> str:
    """Return text formatted in yellow (used for warnings / stats)."""
    return _c("33", t)


def cyan(t: str) -> str:
    """Return text formatted in cyan (used for headers / info lines)."""
    return _c("36", t)


def grey(t: str) -> str:
    """Return text formatted in grey (used for secondary info)."""
    return _c("90", t)


# ---------------------------------------------------------------------------
# Service database — protocol-aware probes & known port names
# ---------------------------------------------------------------------------

# Maps port → bytes to send immediately after connecting.
# Sending the wrong probe (e.g. HTTP HEAD to SSH) gets you nothing;
# service-specific probes get you real banners.
SERVICE_PROBES: dict[int, bytes] = {
    21:    b"",                                   # FTP — server sends banner first
    22:    b"",                                   # SSH — server sends banner first
    23:    b"",                                   # Telnet — server sends first
    25:    b"EHLO scanner\r\n",                   # SMTP
    80:    b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    110:   b"",                                   # POP3 — server sends first
    143:   b"",                                   # IMAP — server sends first
    443:   b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    3306:  b"",                                   # MySQL — server sends greeting first
    5432:  b"",                                   # PostgreSQL
    6379:  b"PING\r\n",                           # Redis
    8080:  b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8443:  b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    27017: b"\x3a\x00\x00\x00\x00\x00\x00\x00"   # MongoDB OP_QUERY probe
           b"\x00\x00\x00\x00\xd4\x07\x00\x00"
           b"\x00\x00\x00\x00admin.$cmd\x00"
           b"\x00\x00\x00\x00\xff\xff\xff\xff"
           b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00",
}

# Well-known port → service name mapping
PORT_NAMES: dict[int, str] = {
    21: "ftp",       22: "ssh",      23: "telnet",   25: "smtp",
    53: "dns",       80: "http",     110: "pop3",    143: "imap",
    443: "https",    445: "smb",     3306: "mysql",  3389: "rdp",
    5432: "psql",    6379: "redis",  8080: "http-alt", 8443: "https-alt",
    9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}

# Regex patterns to extract clean version strings from raw banners
VERSION_PATTERNS: list[re.Pattern] = [
    re.compile(r"SSH-[\d.]+-(?:OpenSSH_)?([\w._-]+)"),          # SSH
    re.compile(r"Server:\s*([\w/._-]+(?:\s[\w/._-]+)?)", re.I), # HTTP Server header
    re.compile(r"([\d]+\.[\d]+\.[\d]+(?:\.[\d]+)?)"),           # Generic x.y.z
]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    """
    Holds the result for a single scanned port.

    Attributes:
        port        TCP port number
        state       Always 'open' (closed ports are not recorded)
        service     Well-known service name, or 'unknown'
        banner      Raw banner text received from the service
        version     Version string parsed out of the banner, if found
        latency_ms  Round-trip connection latency in milliseconds
    """
    port: int
    state: str = "open"
    service: str = "unknown"
    banner: str = ""
    version: str = ""
    latency_ms: float = 0.0


@dataclass
class ScanReport:
    """
    Top-level scan report containing metadata and all open port results.

    Attributes:
        target      IP or hostname that was scanned
        scan_range  Port range string, e.g. "1-1024"
        started_at  ISO timestamp when the scan began
        elapsed_s   Total scan duration in seconds
        ports_total Total number of ports probed
        results     List of ScanResult for every open port found
    """
    target: str
    scan_range: str
    started_at: str
    elapsed_s: float = 0.0
    ports_total: int = 0
    results: list[ScanResult] = field(default_factory=list)

    @property
    def ports_open(self) -> int:
        """Return the count of open ports found."""
        return len(self.results)

    @property
    def scan_rate(self) -> float:
        """Return the average scan rate in ports per second."""
        return round(self.ports_total / self.elapsed_s, 1) if self.elapsed_s > 0 else 0.0


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------

class PortScanner:
    """
    Multi-threaded TCP connect scanner with protocol-aware banner grabbing.

    Design decisions:
        - Uses socket.connect_ex() instead of connect() so we never raise on
          a closed port — error code 0 = open, anything else = closed/filtered.
        - A shared queue.Queue distributes port numbers across worker threads;
          no explicit locking needed on the queue itself.
        - Results list is protected by a threading.Lock — appends from multiple
          threads are not thread-safe by default on all Python implementations.
        - Banner grabbing is done *inside* the worker (not in a second pass) to
          reuse the already-open socket where possible.

    Args:
        host     : Target IP address or hostname
        timeout  : Per-connection timeout in seconds
        threads  : Number of concurrent worker threads
        retries  : How many times to retry a port that raises an exception
    """

    def __init__(
        self,
        host: str,
        timeout: float = 0.5,
        threads: int = 150,
        retries: int = 1,
    ) -> None:
        self.host = host
        self.timeout = timeout
        self.threads = threads
        self.retries = retries
        self._results: list[ScanResult] = []
        self._lock = threading.Lock()
        self._scanned = 0          # atomic-ish counter for progress display
        self._progress_lock = threading.Lock()

    def _resolve_host(self) -> str:
        """
        Resolve the target hostname to an IP address.

        Returns the IP string, or the original host string if resolution fails.
        This lets us display the resolved IP in the report header.
        """
        try:
            return socket.gethostbyname(self.host)
        except socket.gaierror:
            return self.host

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """
        Grab the service banner from an already-connected socket.

        Sends a protocol-appropriate probe byte string (or nothing for services
        that speak first), then reads up to 1024 bytes.  Returns the decoded,
        stripped banner, or an empty string on failure.

        Args:
            sock : An already-connected TCP socket
            port : Port number — used to look up the correct probe
        """
        try:
            probe = SERVICE_PROBES.get(port, b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            if probe:
                sock.sendall(probe)
            raw = sock.recv(1024)
            return raw.decode(errors="ignore").strip()
        except (socket.timeout, OSError):
            return ""

    def _extract_version(self, banner: str) -> str:
        """
        Parse a version string from a raw service banner.

        Tries each pattern in VERSION_PATTERNS in order and returns the first
        match found, or an empty string if no version can be identified.

        Args:
            banner : Raw decoded banner text from the service
        """
        for pattern in VERSION_PATTERNS:
            m = pattern.search(banner)
            if m:
                return m.group(1)
        return ""

    def _scan_port(self, port: int) -> Optional[ScanResult]:
        """
        Attempt a TCP connection to a single port.

        Tries up to self.retries + 1 times.  On success, grabs the banner and
        extracts the version.  Returns a ScanResult if the port is open, or
        None if it is closed/filtered/unreachable.

        Args:
            port : TCP port number to probe
        """
        for attempt in range(self.retries + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            try:
                t0 = time.monotonic()
                err = sock.connect_ex((self.host, port))
                latency = (time.monotonic() - t0) * 1000  # ms

                if err == 0:  # port is open
                    banner = self._grab_banner(sock, port)
                    return ScanResult(
                        port=port,
                        service=PORT_NAMES.get(port, "unknown"),
                        banner=banner[:200],
                        version=self._extract_version(banner),
                        latency_ms=round(latency, 2),
                    )
                return None  # closed or filtered — no point retrying
            except OSError:
                if attempt == self.retries:
                    return None
            finally:
                sock.close()
        return None

    def _worker(self, port_queue: queue.Queue) -> None:
        """
        Thread worker: drain the port queue, scan each port, collect results.

        Args:
            port_queue : Shared queue of port integers to scan
        """
        while True:
            try:
                port = port_queue.get_nowait()
            except queue.Empty:
                break

            result = self._scan_port(port)

            # Update progress counter (approximate — not using an atomic int)
            with self._progress_lock:
                self._scanned += 1

            if result:
                with self._lock:
                    self._results.append(result)

            port_queue.task_done()

    def scan(self, ports: list[int]) -> ScanReport:
        """
        Run the full scan against the provided port list.

        Spins up self.threads worker threads, waits for all to finish, then
        returns a ScanReport with every open port found.

        Args:
            ports : List of integer port numbers to scan

        Returns:
            ScanReport instance populated with scan metadata and results
        """
        started_at = datetime.now()
        port_queue: queue.Queue = queue.Queue()
        for p in ports:
            port_queue.put(p)

        total = len(ports)
        workers = [
            threading.Thread(target=self._worker, args=(port_queue,), daemon=True)
            for _ in range(min(self.threads, total))
        ]
        for w in workers:
            w.start()

        # Progress display — runs on main thread while workers are busy
        while any(w.is_alive() for w in workers):
            with self._progress_lock:
                done = self._scanned
            pct = int(done / total * 40) if total else 40
            bar = "=" * pct + "-" * (40 - pct)
            print(f"\r  [{bar}] {done}/{total}", end="", flush=True)
            time.sleep(0.15)

        for w in workers:
            w.join()
        print()  # newline after progress bar

        elapsed = (datetime.now() - started_at).total_seconds()
        report = ScanReport(
            target=self.host,
            scan_range=f"{min(ports)}-{max(ports)}",
            started_at=started_at.isoformat(),
            elapsed_s=round(elapsed, 2),
            ports_total=total,
            results=sorted(self._results, key=lambda r: r.port),
        )
        return report


# ---------------------------------------------------------------------------
# Port range parser
# ---------------------------------------------------------------------------

def parse_ports(spec: str) -> list[int]:
    """
    Parse a flexible port specification into a sorted list of integers.

    Supports:
        "1-1024"            → range
        "22,80,443"         → explicit list
        "22,80,8000-8090"   → mixed (list + range)
        "top100"            → built-in top-100 common ports

    Args:
        spec : Port specification string from the CLI

    Returns:
        Sorted, deduplicated list of port numbers

    Raises:
        ValueError if a token cannot be parsed or a port number is out of range
    """
    TOP_100 = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993,
        995, 1723, 3306, 3389, 5900, 8080, 8443, 8888, 9200, 27017, 6379,
        5432, 2181, 11211, 50070, 4848, 1099, 7001, 9090, 8161, 61616,
        2375, 2376, 4243, 5000, 5001, 9000, 9001, 4444, 6666, 1337, 31337,
    ]

    if spec.lower() == "top100":
        return sorted(set(TOP_100))

    ports: set[int] = set()
    for token in spec.split(","):
        token = token.strip()
        if "-" in token:
            start_s, end_s = token.split("-", 1)
            start, end = int(start_s), int(end_s)
            if not (1 <= start <= end <= 65535):
                raise ValueError(f"Invalid range: {token}")
            ports.update(range(start, end + 1))
        else:
            p = int(token)
            if not (1 <= p <= 65535):
                raise ValueError(f"Port out of range: {p}")
            ports.add(p)

    return sorted(ports)


# ---------------------------------------------------------------------------
# Output rendering
# ---------------------------------------------------------------------------

def print_report(report: ScanReport) -> None:
    """
    Render a ScanReport to stdout in a human-readable table format.

    Args:
        report : Completed ScanReport from PortScanner.scan()
    """
    ip = report.target
    print()
    print(cyan(f"  Scan report for {ip}"))
    print(cyan(f"  Started : {report.started_at}"))
    print(cyan(f"  Elapsed : {report.elapsed_s}s  |  "
               f"Rate : {report.scan_rate} ports/sec  |  "
               f"Probed : {report.ports_total}"))
    print()

    if not report.results:
        print(yellow("  No open ports found in the specified range."))
        return

    # Header
    print(f"  {'PORT':<8} {'SERVICE':<14} {'LATENCY':>10}  {'VERSION / BANNER'}")
    print(f"  {'-'*7}  {'-'*13}  {'-'*9}  {'-'*50}")

    for r in report.results:
        port_str = green(f"{r.port}/tcp")
        svc = r.service
        lat = grey(f"{r.latency_ms:.1f} ms")
        # Show version if extracted, else first 60 chars of banner
        detail = r.version if r.version else r.banner.replace("\n", " ")[:60]
        print(f"  {port_str:<20} {svc:<14} {lat:>18}  {detail}")

    print()
    print(f"  {green(str(report.ports_open))} open port(s) found out of "
          f"{report.ports_total} probed.")


def save_json(report: ScanReport, path: str) -> None:
    """
    Serialize the ScanReport to a JSON file.

    Args:
        report : Completed ScanReport
        path   : Destination file path
    """
    data = asdict(report)
    data["ports_open"] = report.ports_open
    data["scan_rate_per_sec"] = report.scan_rate
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    print(cyan(f"\n  [+] Report saved → {path}"))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """
    Build and return the CLI argument parser.

    Returns:
        Configured ArgumentParser instance
    """
    p = argparse.ArgumentParser(
        prog="port_scanner.py",
        description=(
            "Professional TCP port scanner with protocol-aware banner grabbing.\n"
            "Port syntax: '1-1024'  |  '22,80,443'  |  '22,80,8000-8090'  |  'top100'"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("host", help="Target IP address or hostname")
    p.add_argument(
        "-p", "--ports", default="1-1024", metavar="PORTS",
        help="Port specification (default: 1-1024)"
    )
    p.add_argument(
        "-t", "--threads", type=int, default=150, metavar="N",
        help="Worker thread count (default: 150)"
    )
    p.add_argument(
        "--timeout", type=float, default=0.5, metavar="SECS",
        help="Per-connection timeout in seconds (default: 0.5)"
    )
    p.add_argument(
        "--retries", type=int, default=1, metavar="N",
        help="Retry count for failed connections (default: 1)"
    )
    p.add_argument(
        "--json", metavar="FILE",
        help="Save full report as JSON to FILE"
    )
    return p


def main() -> None:
    """
    Parse CLI arguments, run the scan, display results, and optionally save JSON.
    """
    parser = build_parser()
    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"[!] Invalid port specification: {e}")
        sys.exit(1)

    print(cyan(f"\n  port_scanner.py  |  target: {args.host}"))
    print(cyan(f"  ports: {args.ports} ({len(ports)} total)  |  "
               f"threads: {args.threads}  |  timeout: {args.timeout}s"))
    print()

    scanner = PortScanner(
        host=args.host,
        timeout=args.timeout,
        threads=args.threads,
        retries=args.retries,
    )
    report = scanner.scan(ports)
    print_report(report)

    if args.json:
        save_json(report, args.json)


if __name__ == "__main__":
    main()
