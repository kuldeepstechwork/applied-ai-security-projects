#!/usr/bin/env python3
"""
fw_behavior_tester.py — Advanced Firewall Action Diagnostic Tool
================================================================
Project 09 · Module 01 · Week 01

Analyzes TCP handshake failures to determine the target's firewall policy.
Identifies:
  - OPEN: Connection established
  - CLOSED (REJECT): Instant RST packet received (Service down)
  - FILTERED (DROP): Silent timeout (Firewall DROP rule)
  - FILTERED (REJECT): ICMP Unreachable received (explicit block)

Author : Applied AI Security Projects
Lab    : 192.168.100.0/24 | Kali .10 | Webserver .30
"""

from __future__ import annotations

import argparse
import errno
import socket
import sys
import time
from dataclasses import dataclass
from typing import List, Tuple


# ---------------------------------------------------------------------------
# ANSI color helpers
# ---------------------------------------------------------------------------

_USE_COLOR = sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text

def green(t: str) -> str:   return _c("32;1", t)
def yellow(t: str) -> str:  return _c("33", t)
def cyan(t: str) -> str:    return _c("36", t)
def red(t: str) -> str:     return _c("31;1", t)
def bold(t: str) -> str:    return _c("1", t)
def grey(t: str) -> str:    return _c("90", t)


# ---------------------------------------------------------------------------
# Diagnostics Model
# ---------------------------------------------------------------------------

@dataclass
class PortBehavior:
    port: int
    state: str
    reason: str
    latency_ms: float

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    8080: "Proxy", 9000: "App"
}


# ---------------------------------------------------------------------------
# Logic
# ---------------------------------------------------------------------------

class BehaviorTester:
    def __init__(self, host: str, timeout: float = 2.0) -> None:
        self.host = host
        self.timeout = timeout

    def test_port(self, port: int) -> PortBehavior:
        """
        Differentiates between connection failure modes.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        
        start_time = time.monotonic()
        try:
            err = s.connect_ex((self.host, port))
            latency = (time.monotonic() - start_time) * 1000
            
            if err == 0:
                return PortBehavior(port, "OPEN", "Handshake Completed", latency)
            
            # Map errno to behavior
            if err == errno.ECONNREFUSED:
                return PortBehavior(port, "CLOSED", "RST (Connection Refused)", latency)
            elif err in (errno.ETIMEDOUT, errno.EHOSTUNREACH):
                return PortBehavior(port, "FILTERED", "DROP (No response / Timeout)", latency)
            else:
                return PortBehavior(port, "FILTERED", f"Error {err} ({errno.errorcode.get(err, 'UNK')})", latency)

        except socket.timeout:
            latency = (time.monotonic() - start_time) * 1000
            return PortBehavior(port, "FILTERED", "DROP (Silent Timeout)", latency)
        except Exception as e:
            latency = (time.monotonic() - start_time) * 1000
            return PortBehavior(port, "ERROR", str(e), latency)
        finally:
            s.close()

    def run(self, ports: List[int]) -> None:
        print(cyan(f"\n[*] Testing behavior for {bold(self.host)} (Timeout: {self.timeout}s)"))
        print(grey(f"  {'PORT':<8} {'SERVICE':<12} {'STATE':<10} {'DIAGNOSTIC REASON'}") )
        print(grey(f"  {'-'*45}"))

        for p in ports:
            b = self.test_port(p)
            svc = COMMON_PORTS.get(p, "unknown")
            
            state_str = b.state
            if b.state == "OPEN": state_str = green(state_str)
            elif b.state == "CLOSED": state_str = yellow(state_str)
            elif b.state == "FILTERED": state_str = red(state_str)
            
            print(f"  {b.port:<8} {svc:<12} {state_str:<20} {b.reason}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_port_range(spec: str) -> List[int]:
    if "-" in spec:
        start, end = map(int, spec.split("-"))
        return list(range(start, end + 1))
    return [int(p) for p in spec.split(",")]

def main() -> None:
    parser = argparse.ArgumentParser(description="Professional Firewall Behavior Tester")
    parser.add_argument("host", help="Target IP or hostname")
    parser.add_argument("-p", "--ports", default="22,80,443,3306,8080", help="Ports to test (e.g., 80,443 or 1-100)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Socket timeout")
    
    args = parser.parse_args()
    
    try:
        port_list = parse_port_range(args.ports)
    except:
        print(red("[!] Invalid port specification."))
        sys.exit(1)
        
    tester = BehaviorTester(args.host, args.timeout)
    tester.run(port_list)

if __name__ == "__main__":
    main()
