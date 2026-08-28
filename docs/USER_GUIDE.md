# SentinelRecon User Guide

SentinelRecon v1.1.0 is an adaptive reconnaissance and evidence correlation engine designed for authorized penetration testing, security audits, and laboratory environments.

## 1. CLI Reference

- `sentinelrecon`: Launches the interactive reconnaissance wizard.
- `sentinelrecon --help`: Displays the help menu and available commands.
- `sentinelrecon --version`: Displays the installed version (v1.1.0).

*(Note: The legacy command `reconforge` is available as a compatibility alias)*

### Command-Line Arguments & Direct Scanning

```bash
# Scan an IP address (STANDARD mode)
sentinelrecon 10.49.128.206

# Scan with LOW-IMPACT reconnaissance mode
sentinelrecon 10.10.10.25 --mode low-impact

# Scan a specific HTTP service URL
sentinelrecon -u http://10.49.128.206:8080

# Scan an HTTPS service URL
sentinelrecon --url https://target.example.com
```

### Interactive Mode

Running `sentinelrecon` without arguments presents the interactive workflow:

1. **Enter IP or URL**: Target IP address or HTTP/HTTPS URL.
2. **Recon Mode**:
   - `STANDARD`: Complete first-level reconnaissance (port scanning, service detection, OS detection, web probing, technology fingerprinting, content discovery, and evidence-based vulnerability intelligence).
   - `LOW-IMPACT`: Reduced-intensity reconnaissance (respects Retry-After, avoids duplicate requests).
3. **Content Discovery Profile**:
   - `COMMON`: High-signal baseline discovery (admin, auth, api, reports, secrets, robots.txt).
   - `MEDIUM`: Expanded path discovery (backup files, configuration endpoints).
   - `DEEP`: Maximum coverage profile for authorized deep assessments.

---

## 2. Session Management & Reports

Every scan creates a unique, collision-safe session under `~/.sentinelrecon/sessions/session_<timestamp>`. Previous scans are never overwritten.

### Managing Sessions

```bash
# List all saved sessions
sentinelrecon sessions

# View terminal report of a session (or current for latest)
sentinelrecon show current
sentinelrecon show session_2026-08-28_12-00-00

# Export reports in different formats
sentinelrecon report current --format terminal
sentinelrecon report current --format json --output scan.json
sentinelrecon report current --format html --output scan.html

# View WAF / CDN analysis for a session
sentinelrecon waf current
```

---

## 3. Offline Log Ingestion & Analysis

SentinelRecon can analyze existing tool outputs from previous engagements:

```bash
# Import an entire directory of scan results
sentinelrecon import /path/to/logs/

# Analyze a single tool output file
sentinelrecon analyze /path/to/nmap.xml
```

Supported formats: Nmap XML, DNS output, HTTP headers/response, SMB logs, TLS records, Gobuster text, Dirb text, WhatWeb output, and generic text logs.

---

## 4. Tool Registry & Capabilities

```bash
# Check status of underlying application capabilities and providers
sentinelrecon tools
```
