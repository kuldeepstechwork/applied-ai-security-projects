# Project 08 — Professional Local Service Enumerator

**Author: Kuldeep Singh**

---

**Advanced post-exploitation asset discovery engine designed for identifying internal attack surfaces, sensitive configuration artifacts, and potential lateral movement vectors.**

## Security Researcher Perspective

Gaining a "foothold" is only the beginning. This tool automates the critical **Internal Reconnaissance** phase, mapping the target's internal landscape to identify services that are not exposed to the external network. It focuses on **Service-to-Process Correlation** and **Secret Hunting**, providing researchers with a structured view of the target's internal security posture and identifying low-hanging fruit for privilege escalation and pivoting.

## Technical Differentiators

| Feature | Standard OS Commands | This Enumeration Engine |
|---------|-----------------------|-------------------------|
| **Service Mapping** | Raw `ss -tulnp` | **Binding Analysis**: Localhost vs. Public interface |
| **Process Context** | Generic `ps aux` | **High-Value Filtering**: Database, Web, Root-owned processes |
| **Secret Hunting** | Manual `find` strings | **Pattern-Matched Recursive Search**: .env, .git, id_rsa, config files |
| **Pivoting Intel** | Text output | **Contextual Highlighting** of "Internal Only" bind addresses |
| **PrivEsc Discovery** | Manual audit | **Automated Permission Auditing** of sensitive OS files |
| **Operational Impact** | Static data | **Structured Reporting** for rapid post-compromise decision making |

## Professional Engineering Features

- **Pivoting Analysis Engine**: Automatically categorizes services bound to `127.0.0.1` as "Post-Exploitation Targets" vs. those on `0.0.0.0`, streamlining the identification of pivoting opportunities.
- **Deep-File Secret Hunting**: Features a pre-configured library of sensitive file patterns (e.g., `id_rsa`, `.git`, `settings.py`, `config.php`) to locate hardcoded credentials in seconds.
- **Security Posture Summary**: Generates a consolidated, human-readable report detailing the host's high-risk areas, tailored for red team reporting.
- **Zero-Dependency Architecture**: Built for portability, requiring only a Python interpreter and standard Linux utilities, ensuring consistency across various target distributions.

## Usage

```bash
# Full Recon: Execute all enumeration modules
python3 enum_local.py

# Credential Hunting: Focus exclusively on secret/config discovery
python3 enum_local.py --secrets

# Operational Logging: Save structured report for later analysis
python3 enum_local.py --output internal_recon.txt
```

## Security Lab Note

This engine is designed for the **Post-Exploitation** phase of a red team operation. Mastering internal enumeration is the key to transitioning from a simple "foothold" to a full "compromise" through lateral movement and persistence.

