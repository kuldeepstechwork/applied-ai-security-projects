#!/usr/bin/env python3
"""
recon_multitool.py — Consolidated Reconnaissance Engine
========================================================
Project 10 · Module 01 · Week 01

A multi-threaded reconnaissance tool that combines:
  1. TCP Port Scanning (Connect Scan)
  2. Service Banner Grabbing
  3. HTTP Endpoint Enumeration (Pivoted)
  4. Structured JSON Reporting

Author : Applied AI Security Projects
Lab    : 192.168.100.0/24 | Kali .10 | Webserver .30
"""

from __future__ import annotations

import argparse
import json
import queue
import socket
import sys
import threading
import time
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Dict, Optional, Any


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
def grey(t: str) -> str:    return _c("90", t)


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class ReconResult:
    port: int
    state: str = "open"
    banner: str = ""
    is_http: bool = False
    http_paths: List[str] = field(default_factory=list)

@dataclass
class ReconReport:
    target: str
    started_at: str
    elapsed_s: float = 0.0
    results: List[ReconResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Core Recon Logic
# ---------------------------------------------------------------------------

class ReconEngine:
    def __init__(self, host: str, timeout: float = 0.5, threads: int = 100) -> None:
        self.host = host
        self.timeout = timeout
        self.threads = threads
        self.results: List[ReconResult] = []
        self._lock = threading.Lock()
        
    def grab_banner(self, sock: socket.socket) -> str:
        """Attempts to read a service banner."""
        try:
            # Send a generic probe for HTTP/Service ID
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode(errors="ignore").strip()
            return banner[:200]
        except:
            return ""

    def check_http_paths(self, port: int) -> List[str]:
        """Discovery of common sensitive endpoints if HTTP is detected."""
        paths = ["/", "/.env", "/admin", "/config.php", "/.git/config", "/backup"]
        found = []
        for path in paths:
            url = f"http://{self.host}:{port}{path}"
            try:
                # Custom Request to handle timeouts and headers
                req = urllib.request.Request(url, method="HEAD")
                with urllib.request.urlopen(req, timeout=1.0) as response:
                    if response.status == 200:
                        found.append(path)
            except:
                continue
        return found

    def scan_worker(self, q: queue.Queue):
        while not q.empty():
            port = q.get()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            
            try:
                if s.connect_ex((self.host, port)) == 0:
                    banner = self.grab_banner(s)
                    is_http = "HTTP" in banner or port in (80, 443, 8080)
                    
                    res = ReconResult(port=port, banner=banner, is_http=is_http)
                    
                    if is_http:
                        res.http_paths = self.check_http_paths(port)
                        
                    with self._lock:
                        self.results.append(res)
            except:
                pass
            finally:
                s.close()
                q.task_done()

    def run(self, ports: List[int]) -> ReconReport:
        start_time = datetime.now()
        q = queue.Queue()
        for p in ports: q.put(p)
        
        print(cyan(f"[*] Starting Multi-Tool Recon on {self.host}..."))
        
        threads = []
        for _ in range(min(self.threads, len(ports))):
            t = threading.Thread(target=self.scan_worker, args=(q,))
            t.daemon = True
            t.start()
            threads.append(t)
            
        q.join()
        
        elapsed = (datetime.now() - start_time).total_seconds()
        return ReconReport(
            target=self.host,
            started_at=start_time.isoformat(),
            elapsed_s=round(elapsed, 2),
            results=sorted(self.results, key=lambda x: x.port)
        )


# ---------------------------------------------------------------------------
# CLI Helpers
# ---------------------------------------------------------------------------

def print_report(report: ReconReport) -> None:
    print(cyan(f"\n[+] Recon Report for {report.target}"))
    print(grey(f"    Started at: {report.started_at} | Elapsed: {report.elapsed_s}s"))
    print(f"\n  {'PORT':<8} {'BANNER / SERVICE CONTENT'}")
    print(f"  {'-'*45}")
    
    for r in report.results:
        print(f"  {green(str(r.port)):<18} {r.banner[:60]}")
        if r.http_paths:
            for path in r.http_paths:
                print(f"    {yellow('└──')} Found Endpoint: {yellow(path)}")

def main() -> None:
    parser = argparse.ArgumentParser(description="Professional Multi-Tool Recon Script")
    parser.add_argument("host", help="Target IP or hostname")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range or 'top100'")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Concurrency level")
    parser.add_argument("--json", help="Save output to JSON file")
    
    args = parser.parse_args()
    
    # Simple port parser
    if args.ports == "top100":
        port_list = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443, 10000]
    elif "-" in args.ports:
        s, e = map(int, args.ports.split("-"))
        port_list = list(range(s, e + 1))
    else:
        port_list = [int(p) for p in args.ports.split(",")]
        
    engine = ReconEngine(args.host, threads=args.threads)
    report = engine.run(port_list)
    
    print_report(report)
    
    if args.json:
        with open(args.json, "w") as f:
            json.dump(asdict(report), f, indent=4)
        print(cyan(f"\n[!] Full report saved to {args.json}"))

if __name__ == "__main__":
    main()
