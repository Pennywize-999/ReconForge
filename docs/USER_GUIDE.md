# ReconForge User Guide

ReconForge v1.0.0 is a first-level reconnaissance engine that combines network discovery, DNS intelligence, service-aware enumeration, web technology detection, content discovery, vulnerability intelligence, correlation, and clean reporting into one guided workflow.

## 1. CLI Reference

- `reconforge`: Launches the interactive reconnaissance wizard.
- `reconforge --help`: Displays the help menu and available commands.
- `reconforge --version`: Displays the installed version (v1.0.0).

### Command-Line Arguments & Direct Scanning

```bash
# Scan an IP address (STANDARD mode, all TCP ports, service detection)
reconforge 10.10.10.25

# Scan with LOW-IMPACT reconnaissance mode
reconforge 10.10.10.25 --mode low-impact

# Scan a specific HTTP service URL
reconforge -u http://10.10.10.25:8080

# Scan an HTTPS service URL
reconforge --url https://target.example.com
```

### Interactive Mode

Running `reconforge` without arguments presents the interactive workflow:

1. **Enter IP or URL**: Target IP address or HTTP/HTTPS URL.
2. **Recon Mode**:
   - `STANDARD`: Complete first-level reconnaissance (all TCP ports, default NSE scripts, service/version detection, OS detection, web probing, bounded technology fingerprinting, content discovery, verified vulnerability matching).
   - `LOW-IMPACT`: Reduced-intensity reconnaissance (top-1000 ports, skips secondary fingerprinting, respects rate-limiting).
3. **Content Discovery Profile**:
   - `COMMON`: High-signal baseline discovery (admin, auth, api, reports, secrets, robots.txt, dynamic application categories).
   - `EXTENDED`: Broadened path enumeration.
   - `DEEP`: Maximum coverage profile for authorized deep scanning.

---

## 2. Session Management & Reports

Every scan creates a unique, collision-safe session under `~/.reconforge/sessions/session_<timestamp>`. Previous scans are never overwritten.

### Managing Sessions

```bash
# List all saved sessions
reconforge sessions

# View terminal report of a session (or current for latest)
reconforge show current
reconforge show session_2026-08-28_12-00-00_000000

# Export reports in different formats
reconforge report current --format terminal
reconforge report current --format json --output scan.json
reconforge report current --format html --output scan.html

# View WAF / CDN analysis for a session
reconforge waf current
```

---

## 3. Offline Log Ingestion & Analysis

ReconForge can analyze existing tool outputs from previous engagements:

```bash
# Import an entire directory of scan results
reconforge import /path/to/logs/

# Analyze a single tool output file
reconforge analyze /path/to/nmap.xml
```

Supported formats: Nmap XML, DNS output, HTTP headers/response, SMB logs, TLS records, Gobuster text, Dirb text, WhatWeb output, and generic text logs.

---

## 4. Tool Registry

```bash
# Check status of underlying system tools
reconforge tools
```

