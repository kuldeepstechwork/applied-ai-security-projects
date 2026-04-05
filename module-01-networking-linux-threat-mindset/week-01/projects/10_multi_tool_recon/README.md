# Project 10 — Professional Multi-Tool Recon Engine

**Author: Kuldeep Singh**

---

**Unified reconnaissance framework orchestrals tactical port scanning, banner fingerprinting, and targeted web endpoint discovery into a high-performance automated workflow.**

## Security Researcher Perspective

Reconnaissance is the foundation of every successful operation. This tool moves beyond fragmented data gathering by implementing an **Automated Pivot Workflow**. Instead of running multiple disconnected tools, it intelligently adapts its strategy: discovering open ports, immediately grabbing service banners, and—if an HTTP service is identified—automatically launching a targeted "Sanity Check" for high-value web artifacts like `.env` files or admin consoles.

## Technical Differentiators

| Feature | Fragmented Toolset | This Unified Engine |
|---------|-------------------|---------------------|
| **Execution Model** | Manual `nmap` → `curl` | **Atomic Discovery-to-Action Pipeline** |
| **Service Intelligence** | Port-based guess | **Real-Time Protocol Fingerprinting** |
| **Web Reconnaissance** | Separate `gobuster` scan | **Instant Context-Aware Fuzzing** |
| **Data Orchestration** | Disjointed outputs | **Consolidated Research Report** (Table + JSON) |
| **Performance** | Redundant handshakes | **Optimized Socket Reuse** for concurrent probes |

## Professional Engineering Features

- **Pivoted Intelligence Engine**: Features a "Reactive Probing" logic that executes web-specific modules *only* upon confirmed HTTP/S service discovery, drastically reducing noise.
- **High-Concurrency Thread Pooling**: Capable of scanning hundreds of ports per second through a non-blocking `queue` architecture.
- **High-Value Artifact Library**: Includes a curated "Quick Fuzz" wordlist targeting common misconfigurations (e.g., `/config`, `/.git`, `/phpinfo`, `/.env`).
- **Structured Data Portability**: Full JSON export support, ensuring compatibility with downstream automated analysis and reporting pipelines.

## Usage

```bash
# Tactical Recon: Comprehensive scan of a target host
python3 recon_multitool.py 192.168.100.30

# Speed Recon: Quick Top-100 scan with structured JSON output
python3 recon_multitool.py 192.168.100.30 --ports top100 --json recon.json

# Intensive Audit: High-concurrency recon for large-scale assets
python3 recon_multitool.py 192.168.100.30 -t 200 --timeout 0.2
```

## Security Lab Note

This engine represents the "Full Spectrum" of the **Information Gathering** phase. It is designed to provide researchers with a high-fidelity map of a target's exposed services and immediate configuration vulnerabilities in a single, professional execution.

