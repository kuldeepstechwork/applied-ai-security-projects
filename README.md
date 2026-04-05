# Applied AI Security Journey 🛡️
Developing professional-grade security tools and methodologies — from networking fundamentals to AI-specific attack and defense.

This repository chronicles my 12-module practical security engineering journey. Every project is hands-on, built in a dedicated lab environment to understand the "under the hood" mechanics of modern security.

---

## 🏆 Current Progress: Module 01 COMPLETE
**Focus:** Networking · Linux internals · Attacker Threat Mindset

| Module | Topic | Status | Projects |
|--------|-------|--------|----------|
| **01** | **Networking · Linux · Threat Mindset** | ✅ **100%** | **11 Tools** |
| 02 | AI Security Foundations | ⏳ Next | — |
| 03–12 | Advanced Attack & Defense Orchestration | ⏳ TBD | — |

---

## 🛠️ Module 01 — Project Showcase
Built over 18 days of intensive lab work, these 11 tools explore the full lifecycle of a network-based attack, from reconnaissance to post-exploitation.

### Phase 1: Reconnaissance & Enumeration
- **[01] Smart Port Scanner:** TCP/UDP scanning with multi-threading.
- **[02] Network Mapper:** ARP-based local network discovery.
- **[03] Banner Grabber:** Service version detection via socket interaction.
- **[10] Multi-Tool Recon Engine:** A unified suite combining passive and active discovery.

### Phase 2: Traffic Analysis & Monitoring
- **[04] DPI Packet Sniffer:** Real-time traffic analysis using Scapy (ARP, DNS, HTTP layer dissection).
- **[09] Firewall Behavior Tester:** Validating ingress/egress rules and identifying filtered vs. closed ports.

### Phase 3: Exploitation & Payloads
- **[05] Shell Payload Generator:** Automating the creation of multi-platform reverse shells (Python, Bash, Netcat).
- **[06] Credential Auditor:** Brute-force and wordlist auditor for SSH and HTTP services.
- **[07] Attack Surface Simulator:** Emulating web-based attacks to test application-layer resilience.

### Phase 4: Local Enumeration & Post-Exploitation
- **[08] Local Service Enumerator:** Auditing listening ports and system processes on compromised hosts.
- **[11] Attack Chain Simulator:** A capstone project simulating an end-to-end "Kill Chain" within the lab environment.

---

## 🔬 Lab Environment
All tools are tested in a high-fidelity virtual lab environment designed to replicate real-world enterprise infrastructure.

- **Platform:** Mac M4 (Apple Silicon) · VMware Fusion
- **Network Architecture:** `192.168.100.0/24` Isolated VLAN
- **Active Nodes:**
  - **Attacker (`.10`):** Kali Linux (Primary workstation)
  - **Victim (`.20`):** Debian Client (Target for local enumeration)
  - **Target (`.30`):** Webserver (Endpoint for recon and traffic analysis)
  - **Gateway (`.1`):** Ubuntu Router/Firewall (Traffic orchestration)

---

## 🔗 Technical Insights
For a deep dive into the engineering challenges and the "attacker's mindset" shifts experienced during this module, read the full wrap-up on my engineering blog:
👉 **[Module 1 Security Review — Day 18](https://kuldeepstechwork.com/blog/day-18-module-1-wrap-up-security-tools-review)**

---
**Maintained by [Kuldeep Singh](https://kuldeepstechwork.com)**
