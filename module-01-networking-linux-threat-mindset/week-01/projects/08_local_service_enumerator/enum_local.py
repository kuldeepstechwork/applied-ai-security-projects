#!/usr/bin/env python3
"""
enum_local.py — Post-Exploitation Internal Enumerator
=====================================================
Project 08 · Module 01 · Week 01

A comprehensive reconnaissance tool for internal host auditing.
Analyzes:
  1. Network Sockets (ss) - Distinguishes localhost vs public
  2. Running Processes (ps) - Identifies high-value services
  3. Sensitive Files (find) - Hunts for credentials and keys
  4. Host Context - Kernel version, users, and environment

Author : Applied AI Security Projects
Lab    : 192.168.100.0/24 | Kali .10 | Webserver .30
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional


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
def dim(t: str) -> str:     return _c("90", t)
def bold(t: str) -> str:    return _c("1", t)


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class Service:
    protocol: str
    local_address: str
    port: str
    process_name: str
    is_localhost: bool

@dataclass
class EnumerationReport:
    hostname: str
    timestamp: str
    kernel: str
    current_user: str
    services: List[Service] = field(default_factory=list)
    processes: List[str] = field(default_factory=list)
    secrets: List[Dict[str, str]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Core Enumerator
# ---------------------------------------------------------------------------

class LocalEnumerator:
    """
    Orchestrates the discovery of internal artifacts on a Linux host.
    """

    def __init__(self) -> None:
        self.report = EnumerationReport(
            hostname=self._exec("hostname"),
            timestamp=datetime.now().isoformat(),
            kernel=self._exec("uname -a"),
            current_user=f"{self._exec('whoami')} ({self._exec('id -u')})"
        )

    def _exec(self, cmd: str) -> str:
        """Executes a system command and returns stripped output."""
        try:
            return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip()
        except:
            return "N/A"

    def audit_network(self) -> None:
        """
        Parses 'ss -tulnp' to identify listening services and their visibility.
        """
        output = self._exec("ss -tulnpH")
        if output == "N/A": return

        for line in output.split("\n"):
            parts = line.split()
            if len(parts) < 6: continue
            
            proto = parts[0]
            local = parts[4]
            # Handle IPv6 and different ss formats
            if ":" in local:
                addr, port = local.rsplit(":", 1)
            else:
                addr, port = local, "unknown"
                
            p_info = parts[6] if len(parts) > 6 else "unknown"
            
            is_local = "127.0.0.1" in addr or "::1" in addr
            
            self.report.services.append(Service(
                protocol=proto,
                local_address=addr,
                port=port,
                process_name=p_info,
                is_localhost=is_local
            ))

    def audit_processes(self) -> None:
        """
        Lists high-value running processes.
        """
        output = self._exec("ps aux --sort=-%cpu | head -n 20")
        if output != "N/A":
            self.report.processes = output.split("\n")

    def audit_secrets(self, scan_dirs: List[str]) -> None:
        """
        Searches common directories for sensitive configuration files.
        """
        patterns = [
            ".env", "config.php", "settings.py", "id_rsa", ".ssh/authorized_keys",
            "db_pass", ".bash_history", "config.json", ".git/config"
        ]
        
        for d in scan_dirs:
            if not os.path.exists(d): continue
            for pattern in patterns:
                cmd = f"find {d} -name '{pattern}' -type f 2>/dev/null"
                matches = self._exec(cmd)
                if matches and matches != "N/A":
                    for match in matches.split("\n"):
                        perm = self._exec(f"ls -l {match} | cut -d ' ' -f 1")
                        self.report.secrets.append({"path": match, "perms": perm})

    def print_standard(self) -> None:
        """
        Renders the report to stdout with ANSI colorization.
        """
        r = self.report
        print(f"\n{bold(cyan('=== HOST CONTEXT ==='))}")
        print(f"  {bold('Hostname')}: {r.hostname}")
        print(f"  {bold('User')}:     {green(r.current_user)}")
        print(f"  {bold('Kernel')}:   {dim(r.kernel)}")
        
        print(f"\n{bold(cyan('=== NETWORK SERVICES ==='))}")
        print(f"  {'PROTO':<6} {'PORT':<8} {'BINDING':<15} {'PROCESS'}")
        print(f"  {'-'*45}")
        
        for s in r.services:
            binding = yellow("Localhost") if s.is_localhost else green("Public (0.0.0.0)")
            print(f"  {s.protocol:<6} {s.port:<8} {binding:<24} {s.process_name}")

        if r.secrets:
            print(f"\n{bold(red('=== SENSITIVE FILES FOUND ==='))}")
            for secret in r.secrets:
                print(f"  [{yellow(secret['perms'])}] {secret['path']}")

        print(f"\n{bold(cyan('=== RECENT PROCESSES ==='))}")
        for p in r.processes[1:6]: # Show top 5
            print(f"  {dim(p)}")


# ---------------------------------------------------------------------------
# Main Entry
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Professional Local Service Enumerator")
    parser.add_argument("--secrets", action="store_true", help="Focus only on secret hunting")
    parser.add_argument("--dir", default="/home,/var/www,/etc,/tmp", help="Comma-separated dirs to scan for secrets")
    parser.add_argument("--output", help="Save report to file")
    
    args = parser.parse_args()
    
    enum = LocalEnumerator()
    
    if not args.secrets:
        enum.audit_network()
        enum.audit_processes()
        
    enum.audit_secrets(args.dir.split(","))
    
    enum.print_standard()
    
    if args.output:
        with open(args.output, "w") as f:
            f.write(f"Enumeration Report - {enum.report.hostname}\n")
            f.write(f"Generated: {enum.report.timestamp}\n\n")
            for s in enum.report.services:
                f.write(f"{s.protocol} {s.port} {s.local_address} {s.process_name}\n")
        print(cyan(f"\n[+] Report saved to {args.output}"))

if __name__ == "__main__":
    main()
