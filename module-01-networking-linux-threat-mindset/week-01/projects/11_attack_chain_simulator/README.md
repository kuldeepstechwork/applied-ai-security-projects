# Project 11 — Professional Attack Chain Simulator (Capstone)

**Author: Kuldeep Singh**

---

**End-to-end attack orchestration and forensic evidence generation framework designed to simulate the full Cyber Kill Chain in a controlled, professional environment.**

## Security Researcher Perspective

The "Attack Chain Simulator" is the **Capstone** of this module. It synthesizes the methodologies explored in the previous 10 projects into a single, automated orchestration engine. This tool does not merely "attack"—it generates a **Forensic Gold Standard** log of every phase with millisecond precision. This data is invaluable for training security operations center (SOC) analysts, validating SIEM correlation rules, and measuring the "Time to Detect" against an automated adversary.

## Simulation Lifecycle (Cyber Kill Chain)

| Phase | Tactical Action | Defensive Visibility |
|-------|-----------------|----------------------|
| **1. RECON** | Target Identification | Hostname resolution & ICMP up-check |
| **2. SCAN** | Service Discovery | Multi-threaded port probing (1-1024) |
| **3. ENUM** | Vulnerability Check | Automated HTTP path discovery for secrets |
| **4. DELIVER**| Payload Staging | Dynamic payload generation & HTTP hosting |
| **5. ACCESS** | Initial Foothold | Interactive listener orchestration |
| **6. REPORT** | Forensic Analysis | Real-time structured evidence logging |

## Professional Engineering Features

- **High-Fidelity Chronological Logging**: Every simulation event is recorded to a forensic-grade log (`attack_log.txt`) with precise timestamps and MITRE-aligned category tags.
- **Fail-Fast Operational Logic**: Implements early-exit checks to detect if a target is offline or if key ports are filtered before proceeding to high-noise phases.
- **Automated Lifecycle Cleanup**: Features integrated signal handling to terminate background delivery servers and remove staged payloads, ensuring a "Leave No Trace" operational profile on the researcher host.
- **Modular Plugin Architecture**: Designed for extensibility, allowing researchers to easily swap out recon modules or delivery payloads for different operational scenarios.

## Usage

```bash
# Full Spectrum Simulation: Start automated attack chain against a target
sudo python3 attack_chain_simulator.py 192.168.100.30

# Tactical Configuration: Specify custom LHOST and LPORT for the access phase
sudo python3 attack_chain_simulator.py 192.168.100.30 --lhost 192.168.100.10 --lport 4444
```

## Security Lab Note

This Capstone project maps directly to the **MITRE ATT&CK** framework, covering techniques from Reconnaissance (TA0043) through Initial Access (TA0001). It serves as a critical bridge for understanding the dynamic relationship between the "Speed of the Attacker" and the "Visibility of the Defender."

