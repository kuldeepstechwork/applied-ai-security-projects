#!/usr/bin/env python3
"""
net_mapper.py — Subnet Network Mapper with OS Fingerprinting
=============================================================
Module 01 · Module 1 · Project 2

What makes this different from a basic mapper:
  - Dual-mode host discovery: ICMP ping first, then TCP connect fallback for
    hosts that silently drop ICMP (common on hardened servers and cloud VMs)
  - TTL-based OS fingerprinting: parses ping TTL to infer OS family
    (Linux/Mac ≈ 64, Windows ≈ 128, Cisco/network gear ≈ 255)
  - Hostname resolution: reverse DNS lookup per live host
  - ARP cache lookup: reads the OS ARP table to map IP → MAC address,
    giving you vendor hints (first 3 octets = OUI) without any extra traffic
  - Service labeling: open ports are shown with their well-known service name,
    not just a number
  - Concurrent pipeline: host discovery and port scanning run in parallel
    across all live hosts simultaneously
  - Structured JSON export: machine-readable output for chaining with other
    tools or ingesting into a SIEM

Author : Kuldeep Singh
Lab    : 192.168.100.0/24 | Kali .10 | Webserver .30
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional


# ---------------------------------------------------------------------------
# ANSI color helpers
# ---------------------------------------------------------------------------

_USE_COLOR = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    """Wrap *text* in an ANSI escape code if color output is active."""
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text


def green(t: str) -> str:
    """Format text in bold green — used for live hosts and open ports."""
    return _c("32;1", t)


def yellow(t: str) -> str:
    """Format text in yellow — used for warnings and unknown values."""
    return _c("33", t)


def cyan(t: str) -> str:
    """Format text in cyan — used for section headers."""
    return _c("36", t)


def grey(t: str) -> str:
    """Format text in grey — used for secondary / metadata output."""
    return _c("90", t)


def red(t: str) -> str:
    """Format text in red — used for error output."""
    return _c("31", t)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Ports probed per live host. Covers the most impactful services for recon.
DEFAULT_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017,
]

# Well-known port name map
PORT_NAMES: dict[int, str] = {
    21: "ftp",        22: "ssh",        23: "telnet",     25: "smtp",
    53: "dns",        80: "http",       110: "pop3",      143: "imap",
    443: "https",     445: "smb",       3306: "mysql",    3389: "rdp",
    5432: "psql",     5900: "vnc",      6379: "redis",    8080: "http-alt",
    8443: "https-alt", 9200: "elastic", 11211: "memcache", 27017: "mongodb",
}

# TTL values sent by different OS families in ICMP echo replies.
# Routers decrement TTL; we add a fudge factor so we match even through hops.
TTL_OS_MAP: list[tuple[range, str]] = [
    (range(1,   65),  "Linux / macOS"),
    (range(65, 129),  "Windows"),
    (range(129, 256), "Cisco / Network device"),
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class HostResult:
    """
    Represents the reconnaissance findings for a single live host.

    Attributes:
        ip          IPv4 address as string
        hostname    Reverse-DNS hostname, or empty string if not resolved
        mac         MAC address from ARP cache, or empty string if not found
        os_hint     OS family guessed from TTL (e.g. 'Linux / macOS')
        ttl         TTL value observed in ping reply
        open_ports  Dict mapping port number → service name string
        latency_ms  Round-trip ping latency in milliseconds
    """
    ip: str
    hostname: str = ""
    mac: str = ""
    os_hint: str = "unknown"
    ttl: int = 0
    open_ports: dict[int, str] = field(default_factory=dict)
    latency_ms: float = 0.0


@dataclass
class MapReport:
    """
    Top-level scan report for the entire subnet mapping run.

    Attributes:
        network      CIDR notation of the scanned network (e.g. 192.168.100.0/24)
        started_at   ISO timestamp when the scan started
        elapsed_s    Total duration in seconds
        hosts_probed Total number of IP addresses checked for liveness
        hosts        List of HostResult for every live host discovered
    """
    network: str
    started_at: str
    elapsed_s: float = 0.0
    hosts_probed: int = 0
    hosts: list[HostResult] = field(default_factory=list)

    @property
    def hosts_up(self) -> int:
        """Return the count of live hosts discovered."""
        return len(self.hosts)


# ---------------------------------------------------------------------------
# ARP cache reader
# ---------------------------------------------------------------------------

def read_arp_cache() -> dict[str, str]:
    """
    Parse the OS ARP table to build an IP → MAC mapping.

    Uses `arp -n` (Linux/macOS) which reads the local cache — zero network
    traffic, instant results.  The cache is populated automatically when the
    scanner sends ping/TCP probes, so by the time we read it the live hosts
    should already have entries.

    Returns:
        Dict mapping IP address strings to MAC address strings.
        Returns an empty dict if the arp command fails.
    """
    cache: dict[str, str] = {}
    try:
        out = subprocess.run(
            ["arp", "-n"], capture_output=True, text=True, timeout=5, check=False
        ).stdout
        # Both Linux and macOS produce lines like:
        #   192.168.100.1    ether   aa:bb:cc:dd:ee:ff   C   ens160
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                ip = parts[0]
                # MAC address = 6 hex octets separated by : or -
                mac_candidate = next(
                    (p for p in parts if re.match(r"([0-9a-f]{2}[:\-]){5}[0-9a-f]{2}", p, re.I)),
                    None,
                )
                if mac_candidate and re.match(r"\d+\.\d+\.\d+\.\d+", ip):
                    cache[ip] = mac_candidate.upper()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return cache


# ---------------------------------------------------------------------------
# Host discovery
# ---------------------------------------------------------------------------

def ping_host(ip: str, timeout: int = 1) -> tuple[bool, int, float]:
    """
    Send a single ICMP echo request and parse the reply for TTL and latency.

    We call the system `ping` binary rather than crafting raw ICMP packets so
    we don't need root privileges.  The output is parsed with regex to extract
    TTL and round-trip time.

    Args:
        ip      : Target IP address string
        timeout : Ping wait timeout in seconds

    Returns:
        Tuple of (is_alive: bool, ttl: int, latency_ms: float).
        On failure returns (False, 0, 0.0).
    """
    try:
        # macOS uses -W (milliseconds), Linux uses -W (seconds) — normalise
        flag = ["-W", "1000"] if sys.platform == "darwin" else ["-W", str(timeout)]
        result = subprocess.run(
            ["ping", "-c", "1"] + flag + [ip],
            capture_output=True, text=True, timeout=timeout + 2, check=False,
        )
        if result.returncode != 0:
            return False, 0, 0.0

        stdout = result.stdout
        ttl = 0
        latency = 0.0

        # Extract TTL — appears as "ttl=64" or "TTL=64"
        ttl_match = re.search(r"ttl=(\d+)", stdout, re.I)
        if ttl_match:
            ttl = int(ttl_match.group(1))

        # Extract latency — appears as "time=1.23 ms" or "time=1 ms"
        lat_match = re.search(r"time=([\d.]+)\s*ms", stdout, re.I)
        if lat_match:
            latency = float(lat_match.group(1))

        return True, ttl, latency
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False, 0, 0.0


def tcp_probe(ip: str, port: int = 80, timeout: float = 1.0) -> bool:
    """
    Attempt a TCP connection to detect hosts that block ICMP.

    Some firewalled servers refuse ICMP but accept TCP on common ports.
    We try port 80, then 443, then 22 to maximize discovery without being loud.

    Args:
        ip      : Target IP address string
        port    : TCP port to try (default 80)
        timeout : Connection timeout in seconds

    Returns:
        True if the TCP connection was accepted (port open), False otherwise.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except OSError:
        return False


def is_host_alive(ip: str) -> tuple[bool, int, float]:
    """
    Determine whether a host is alive using a two-stage discovery strategy.

    Stage 1 — ICMP ping: fast, works on most LAN hosts.
    Stage 2 — TCP probe on ports 80, 443, 22: catches hosts that drop ICMP
              (common on cloud VMs and hardened servers).

    Args:
        ip : Target IP address string

    Returns:
        Tuple of (alive: bool, ttl: int, latency_ms: float).
        TTL is 0 and latency is 0.0 when only TCP probe succeeds.
    """
    alive, ttl, latency = ping_host(ip)
    if alive:
        return True, ttl, latency

    # Fall back to TCP probe on common ports
    for port in (80, 443, 22):
        if tcp_probe(ip, port):
            return True, 0, 0.0

    return False, 0, 0.0


def guess_os(ttl: int) -> str:
    """
    Guess the OS family from a ping reply TTL value.

    Initial TTL is decremented by each router hop, so we need tolerant ranges.
    This is a heuristic — treat it as a hint, not a definitive identification.

    Args:
        ttl : TTL integer from the ICMP reply

    Returns:
        Human-readable OS family string, or 'unknown' if TTL is 0.
    """
    if ttl == 0:
        return "unknown (TCP-only discovery)"
    for ttl_range, os_name in TTL_OS_MAP:
        if ttl in ttl_range:
            return os_name
    return f"unknown (TTL={ttl})"


# ---------------------------------------------------------------------------
# Port scanner (per-host, runs after discovery)
# ---------------------------------------------------------------------------

def scan_host_ports(ip: str, ports: list[int], timeout: float = 0.5) -> dict[int, str]:
    """
    TCP connect-scan a list of ports on a single host.

    Runs each port check in its own thread so that all ports are probed
    concurrently — a 20-port scan completes in roughly one timeout period
    regardless of how many ports are filtered/closed.

    Args:
        ip      : Target IP address
        ports   : List of port integers to probe
        timeout : Per-connection timeout in seconds

    Returns:
        Dict mapping open port numbers to their service name strings.
    """
    open_ports: dict[int, str] = {}
    lock = threading.Lock()

    def _check(port: int) -> None:
        """Probe a single port and record result if open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) == 0:
                with lock:
                    open_ports[port] = PORT_NAMES.get(port, "unknown")
            sock.close()
        except OSError:
            pass

    threads = [threading.Thread(target=_check, args=(p,)) for p in ports]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return open_ports


# ---------------------------------------------------------------------------
# Resolver helpers
# ---------------------------------------------------------------------------

def resolve_hostname(ip: str) -> str:
    """
    Perform a reverse DNS lookup for an IP address.

    Args:
        ip : IPv4 address string

    Returns:
        Fully-qualified hostname string, or empty string if lookup fails.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


# ---------------------------------------------------------------------------
# Main mapper
# ---------------------------------------------------------------------------

class NetworkMapper:
    """
    Orchestrates subnet-wide host discovery followed by per-host port scanning.

    Workflow:
        1. Enumerate all host IPs in the given CIDR block.
        2. Concurrently probe each IP for liveness (ICMP + TCP fallback).
        3. For each live host: resolve hostname, look up ARP cache, run port scan.
        4. Assemble a MapReport with all findings.

    Args:
        network      : CIDR notation string, e.g. '192.168.100.0/24'
        ports        : List of ports to check per live host
        threads      : Max concurrent threads for the discovery phase
        timeout      : Network timeout in seconds
    """

    def __init__(
        self,
        network: str,
        ports: Optional[list[int]] = None,
        threads: int = 100,
        timeout: float = 0.5,
    ) -> None:
        self.network = network
        self.ports = ports or DEFAULT_PORTS
        self.threads = threads
        self.timeout = timeout
        self._live: list[HostResult] = []
        self._lock = threading.Lock()

    def _discover_host(self, ip: str, arp_cache: dict[str, str]) -> None:
        """
        Full recon pipeline for a single IP: check liveness, fingerprint, scan ports.

        Called from a worker thread for each IP in the subnet.  Builds a
        HostResult and appends it to self._live if the host responds.

        Args:
            ip        : IPv4 address to investigate
            arp_cache : Pre-fetched ARP table (IP → MAC)
        """
        alive, ttl, latency = is_host_alive(ip)
        if not alive:
            return

        hostname = resolve_hostname(ip)
        mac = arp_cache.get(ip, "")
        os_hint = guess_os(ttl)
        open_ports = scan_host_ports(ip, self.ports, self.timeout)

        result = HostResult(
            ip=ip,
            hostname=hostname,
            mac=mac,
            os_hint=os_hint,
            ttl=ttl,
            open_ports=open_ports,
            latency_ms=latency,
        )
        with self._lock:
            self._live.append(result)
            self._print_live_host(result)

    @staticmethod
    def _print_live_host(host: HostResult) -> None:
        """
        Print a single live host's summary to stdout as it is discovered.

        Args:
            host : Completed HostResult to display
        """
        hostname_str = grey(f"  ({host.hostname})") if host.hostname else ""
        mac_str = grey(f"  MAC: {host.mac}") if host.mac else ""
        ttl_str = grey(f"TTL={host.ttl}") if host.ttl else ""
        lat_str = grey(f"{host.latency_ms:.1f}ms") if host.latency_ms else ""

        print(f"  {green('UP')}  {host.ip:<18}{hostname_str}{mac_str}")
        print(f"       OS hint : {yellow(host.os_hint)}  {ttl_str}  {lat_str}")
        if host.open_ports:
            ports_str = "  ".join(
                f"{green(str(p))}/{svc}" for p, svc in sorted(host.open_ports.items())
            )
            print(f"       Open    : {ports_str}")
        print()

    def run(self) -> MapReport:
        """
        Execute the full subnet scan and return a MapReport.

        Reads the ARP cache before launching threads so all threads can use
        the same snapshot without redundant subprocess calls.

        Returns:
            Populated MapReport instance
        """
        started_at = datetime.now()
        net = ipaddress.ip_network(self.network, strict=False)
        all_ips = [str(ip) for ip in net.hosts()]

        print(cyan(f"\n  [1/2] Host Discovery — {self.network}  ({len(all_ips)} addresses)"))
        print(cyan("        Strategy: ICMP ping → TCP fallback (80, 443, 22)\n"))

        # Snapshot the ARP cache before we start so threads share one copy
        arp_cache = read_arp_cache()

        # Semaphore limits concurrency so we don't flood the network
        sem = threading.Semaphore(self.threads)

        def bounded_discover(ip: str) -> None:
            """Acquire semaphore, discover, release."""
            with sem:
                self._discover_host(ip, arp_cache)

        threads = [threading.Thread(target=bounded_discover, args=(ip,)) for ip in all_ips]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        elapsed = (datetime.now() - started_at).total_seconds()

        return MapReport(
            network=self.network,
            started_at=started_at.isoformat(),
            elapsed_s=round(elapsed, 2),
            hosts_probed=len(all_ips),
            hosts=sorted(self._live, key=lambda h: list(map(int, h.ip.split(".")))),
        )


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def print_summary(report: MapReport) -> None:
    """
    Print a compact summary table of all live hosts and their open services.

    Args:
        report : Completed MapReport
    """
    print(cyan("  ─" * 30))
    print(cyan(f"  SUMMARY — {report.network}"))
    print(cyan("  ─" * 30))
    print(f"  Hosts probed : {report.hosts_probed}")
    print(f"  Hosts up     : {green(str(report.hosts_up))}")
    print(f"  Elapsed      : {report.elapsed_s}s")
    print()

    if not report.hosts:
        print(yellow("  No live hosts found."))
        return

    for h in report.hosts:
        svc_count = len(h.open_ports)
        ports_brief = ", ".join(
            f"{p}/{svc}" for p, svc in sorted(h.open_ports.items())
        ) or grey("none")
        host_label = f"{h.ip}" + (f" ({h.hostname})" if h.hostname else "")
        print(f"  {green(host_label):<40}  {yellow(h.os_hint):<30}  {svc_count} open: {ports_brief}")


def save_json(report: MapReport, path: str) -> None:
    """
    Write the MapReport as indented JSON to a file.

    Args:
        report : Completed MapReport
        path   : Destination file path
    """
    data = asdict(report)
    data["hosts_up"] = report.hosts_up
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    print(cyan(f"\n  [+] Report saved → {path}"))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """
    Build and return the CLI argument parser.

    Returns:
        Configured ArgumentParser instance
    """
    p = argparse.ArgumentParser(
        prog="net_mapper.py",
        description=(
            "Subnet network mapper: ICMP + TCP host discovery, TTL OS fingerprinting,\n"
            "ARP cache MAC lookup, hostname resolution, and per-host port scanning."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("network", nargs="?", default="192.168.100.0/24",
                   help="Target CIDR network (default: 192.168.100.0/24)")
    p.add_argument("-p", "--ports", metavar="PORTS",
                   help="Comma-separated ports to check per host (default: 20 common ports)")
    p.add_argument("-t", "--threads", type=int, default=100,
                   help="Max concurrent discovery threads (default: 100)")
    p.add_argument("--timeout", type=float, default=0.5,
                   help="TCP port probe timeout in seconds (default: 0.5)")
    p.add_argument("--json", metavar="FILE",
                   help="Save full report as JSON to FILE")
    return p


def main() -> None:
    """
    Parse CLI arguments, execute the subnet scan, display results, optionally save JSON.
    """
    parser = build_parser()
    args = parser.parse_args()

    ports = DEFAULT_PORTS
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
        except ValueError as e:
            print(red(f"[!] Invalid port list: {e}"))
            sys.exit(1)

    print(cyan(f"\n  net_mapper.py  |  network: {args.network}"))
    print(cyan(f"  threads: {args.threads}  |  timeout: {args.timeout}s  |  "
               f"ports/host: {len(ports)}"))

    mapper = NetworkMapper(
        network=args.network,
        ports=ports,
        threads=args.threads,
        timeout=args.timeout,
    )
    report = mapper.run()
    print_summary(report)

    if args.json:
        save_json(report, args.json)


if __name__ == "__main__":
    main()
