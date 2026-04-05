# Project 07 — Professional Web Delivery Attack Simulator

**Author: Kuldeep Singh**

---

**Automated payload delivery framework orchestrating staging, hosting, and listener management into a unified, professional execution flow for red team operational modeling.**

## Security Researcher Perspective

Efficient payload delivery is a critical component of the **Initial Access** phase. This tool addresses the "juggling act" researchers often face when managing multiple terminals for payload generation, web hosting, and listener access. It automates the orchestration of these components, enabling researchers to focus on the **Tactical Execution** and **Detections** rather than the infrastructure management.

## Technical Differentiators

| Feature | Manual Red Team Process | This Simulation Engine |
|---------|-------------------------|------------------------|
| **Staging** | Manual script creation | **Templated Dynamic Payload Generation** |
| **Hosting** | Static `http.server` | **Programmatic Access-Logged Web Server** |
| **Listener** | Manual `nc` management | **Automatic Threaded Listener Dispatch** |
| **Operational Flow** | Disjointed/Error-prone | **Sequential Recon → Deliver → Access** |
| **Cleanup** | Orphaned processes | **Integrated Signal-Aware Process Termination** |

## Professional Engineering Features

- **Multi-Process Orchestration**: Leverages advanced `subprocess` management to handle background delivery servers and listeners, keeping the researcher's workspace clean.
- **Dynamic Payload Staging**: Automatically injects LHOST/LPORT parameters into complex shell templates, ensuring every delivery is tailored to the current operation.
- **Audit-Ready Access Tracking**: Real-time monitoring and logging of incoming target requests, providing forensic evidence for simulation reports.
- **Zero-Orphan Cleanup**: Implements robust signal handling to ensure all child processes are terminated upon script exit, maintaining the integrity of the research host.

## Usage

```bash
# Basic Execution: Start simulation with default parameters
sudo python3 attack_server.py

# Tactical Deployment: Specify custom LHOST and HTTP hosting port
sudo python3 attack_server.py --lhost 192.168.100.10 --lport 4444 --http 8080
```

## Security Lab Note

This tool is engineered for **authorized security assessments and laboratory environments only**. It demonstrates the *'curl | bash'* delivery pattern—a prevalent technique in both legitimate DevOps workflows and malicious malware distribution chains. Understanding this pattern is essential for developing high-fidelity detection rules.

