# Project 09 — Professional Firewall Behavior Tester

**Author: Kuldeep Singh**

---

**Advanced diagnostic engine for differentiating between CLOSED, FILTERED, and OPEN ports by performing deep analysis of TCP handshakes and kernel-level socket error codes.**

## Security Researcher Perspective

A standard port scan is a binary check: "is it open?" A professional researcher, however, needs to understand the **Behavior** of the target's network stack. This tool differentiates between a service that is simply not running (RST) and a packet that is being actively dropped or rejected by a perimeter defense (Firewall/IDS). This level of granular visibility is essential for both **Evasion Planning** and **Defense-in-Depth Validation**.

## Technical Differentiators

| Feature | Standard Port Scanner | This Behavior Tester |
|---------|-----------------------|----------------------|
| **Closed Logic** | Generic "Closed" | **RST Detection**: Maps to `ECONNREFUSED` |
| **Stealth Logic** | Conflated with closed | **Silent Drop Detection**: Maps to `ETIMEDOUT` |
| **Policy Analysis** | None | **ICMP-Aware REJECT Detection** |
| **Timing Precision** | Coarse timeouts | **Per-Port Latency & Jitter Profiles** |
| **Diagnostic Reporting** | Port list | **Actionable Intelligence** on *why* a port is blocked |

## Professional Engineering Features

- **Kernel-Level Error Mapping**: Directly translates Python `OSError` codes and errno values to specific firewall actions (DROP vs. REJECT), providing researchers with the exact packet-level response.
- **Adaptive Timeout Orchestration**: Features granular timeout controls to distinguish between high-latency services and firewall-induced packet loss.
- **Operational Policy Audit**: Designed to verify that security policies (e.g., "DROP all but 443") are correctly implemented and do not leak information via ICMP REJECTs.
- **Visual Intelligence Dashboard**: Generates color-coded tables with "STATE" and "REASON" fields, facilitating rapid interpretation of large-scale scan results.

## Usage

```bash
# Policy Audit: Test a target host for common service ports
python3 fw_behavior_tester.py 192.168.100.30

# High-Precision Scan: Target specific ranges with 1s timeout
python3 fw_behavior_tester.py 192.168.100.30 -p 80-100 --timeout 1.0

# Comparative Analysis: Baseline vs Target behavior check
python3 fw_behavior_tester.py 192.168.100.1
python3 fw_behavior_tester.py 192.168.100.30
```

## Security Lab Note

Distinguishing between `DROP` and `REJECT` is fundamental to network security operations. This tool provides the **Attacker's Perspective** of your own defensive posture, helping researchers confirm if their security layers are correctly providing "Stealth" or simply signaling a refusal.

