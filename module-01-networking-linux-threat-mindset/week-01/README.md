# Module 01 — Networking · Linux · Threat Mindset

**Lead Researcher: Kuldeep Singh**

---

## Overview

This module focuses on the intersection of low-level networking, Linux internals, and the attacker's mindset. It contains 11 core security engineering projects and 6 forensics labs designed to simulate the full threat lifecycle—from reconnaissance to post-compromise reporting.

## Projects

| # | Project | Key Security Methodology | Status |
|---|---------|---------------------------|--------|
| 01 | [Port Scanner](./projects/01_port_scanner) | Multi-threaded TCP stack analysis | ✅ Complete |
| 02 | [Network Mapper](./projects/02_network_mapper) | L3/L2 host discovery & subnet mapping | ✅ Complete |
| 03 | [Banner Grabber](./projects/03_banner_grabber) | Service fingerprinting & OS inference | ✅ Complete |
| 04 | [Packet Sniffer](./projects/04_packet_sniffer) | Protocol deserialization & traffic analysis | ✅ Complete |
| 05 | [Shell Payload Generator](./projects/05_shell_payload_generator) | Remote access payload orchestration | ✅ Complete |
| 06 | [Credential Auditor](./projects/06_credential_auditor) | Multi-protocol brute-force & state-aware lockout detection | ✅ Complete |
| 07 | [Web Attack Simulator](./projects/07_web_attack_simulation) | Web delivery payloads & HTTP/S behavior modeling | ✅ Complete |
| 08 | [Local Service Enumerator](./projects/08_local_service_enumerator) | Post-exploitation internal service discovery | ✅ Complete |
| 09 | [Firewall Behavior Tester](./projects/09_firewall_tester) | Rule-set validation via per-protocol probing | ✅ Complete |
| 10 | [Multi-Tool Recon Engine](./projects/10_multi_tool_recon) | Orchestrating multi-layered reconnaissance pipelines | ✅ Complete |
| 11 | [Attack Chain Simulator](./projects/11_attack_chain_simulator) | Capstone: Automated Cyber Kill Chain orchestration | ✅ Complete |

## Core Competencies

- **Python Socket Programming**: Building low-level TCP/UDP clients and servers.
- **Concurrency**: High-speed network operations via `threading` and `queue`.
- **Packet Analysis**: Deep packet inspection (DPI) and protocol parsing.
- **Offensive Methodologies**: Implementing reconnaissance, enumeration, and delivery phases.
- **Defensive Mirroring**: Understanding attacker patterns to improve detection and response.
- **Forensic Logging**: Generating structured evidence logs for SIEM ingestion.

