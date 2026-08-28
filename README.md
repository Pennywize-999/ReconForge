# ReconForge

ReconForge is a first-level reconnaissance engine that combines network discovery, service identification, web reconnaissance, technology fingerprinting, content discovery, evidence collection, correlation, and vulnerability intelligence into one guided workflow.

> [!NOTE]
> **Authorized Use Only**: ReconForge is designed for authorized penetration testing, security assessments, CTFs, and lab environments. Always obtain explicit written authorization before scanning target systems.

---

## Features

- **Automated First-Level Reconnaissance**: Orchestrates host discovery, port scanning, service probing, and web enumeration through a single guided command.
- **Service-Aware Routing**: Inspects discovered open ports and automatically routes relevant web services (HTTP/HTTPS) into specialized web intelligence pipelines without unnecessary or mismatched requests.
- **Accurate Technology Fingerprinting**: Identifies confirmed web servers, CMSs, application frameworks, and frontend libraries using headers, HTML metadata, generator tags, and response bodies without speculative guessing.
- **Targeted Content Discovery**: Leverages prioritized, category-driven wordlists (admin, authentication, APIs, backups, configuration, reports, and secrets) tailored to the target profile.
- **Verified Vulnerability Intelligence (ForgeIntel)**: Correlates detected software products and exact versions against the National Vulnerability Database (NVD 2.0 API), reporting only verified CPE applicability matches to prevent false positives.
- **Persistent, Collision-Safe Sessions**: Saves raw tool outputs, execution logs, normalized target data, and generated reports into unique timestamped session directories.
- **Multi-Format Reporting**: Produces clean terminal summaries, machine-readable JSON exports, and standalone HTML dashboards.

---

## How ReconForge Works

ReconForge executes a structured multi-phase reconnaissance pipeline:

```text
                     Target (IP or URL)
                             |
                             v
                        [ForgeDNS]         <-- Hostname & Reverse DNS
                             |
                             v
                        [ForgeScan]        <-- Port & Service Detection (Nmap)
                             |
                    Service-Aware Routing
                             |
         +-------------------+-------------------+
         |                   |                   |
         v                   v                   v
    [ForgeProbe]        [ForgeTech]       [ForgeDiscover]
   (HTTP Response)    (Fingerprinting)   (Content Discovery)
         |                   |                   |
         +-------------------+-------------------+
                             |
                       [ForgeTLS]          <-- HTTPS & Certificate Intel
                             |
                             v
                        [ForgeCore]        <-- Data Normalization & Fusion
                             |
                             v
                        [ForgeIntel]       <-- Verified NVD CVE Correlation
                             |
                             v
              [Terminal / JSON / HTML Report]
```

1. **DNS Intelligence**: Gathers forward and reverse DNS records.
2. **Network Discovery**: Identifies active hosts, open ports, protocols, services, versions, and operating system hints.
3. **Service Routing**: Dynamically directs discovered HTTP/HTTPS endpoints to web intelligence collectors.
4. **Web Intelligence & Fingerprinting**: Extracts response headers, cookies, application indicators, and certificates.
5. **Content Discovery**: Enumerates high-signal endpoints, administrative interfaces, and configuration assets.
6. **Core Normalization & Correlation**: Deduplicates URLs, normalizes service data, and classifies intelligence.
7. **Vulnerability Assessment**: Queries NVD for verified CVE matches matching exact version applicability bounds.
8. **Report Generation & Persistence**: Saves evidence and renders output across terminal, JSON, and HTML formats.

---

## ReconForge Components

ReconForge unifies specialized reconnaissance engines into cohesive Forge components:

### ForgeScan
Network and service discovery engine backed by Nmap.
- **What it discovers**: Open TCP ports, transport protocols, service banners, exact product names, software versions, and OS detection hints.
- **Integration**: Drives the service-aware routing engine. Only ports with active HTTP/HTTPS services trigger subsequent web reconnaissance.
- **Report Output**: Populates the **OPEN PORTS / SERVICES** table with port, state, service name, product, and version.

### ForgeDNS
DNS intelligence and resolution engine.
- **What it discovers**: Forward hostname resolution, reverse PTR lookups, and host-to-IP associations.
- **Clean Status Handling**: For targets without a DNS or PTR record, ForgeDNS reports `[INFO] ForgeDNS: no DNS record`. A missing record is an informational result, not a failure or warning. True resolver timeouts or connection errors are reported as `[TIMEOUT]` or `[WARN]`.

### ForgeProbe
HTTP/HTTPS service probing collector.
- **What it discovers**: HTTP status codes (200, 301, 302, 401, 403, 500), response headers, redirection paths, cookies, and server banners.
- **Application Extraction**: Captures a bounded response body to detect embedded application markers, generator meta tags, and framework scripts that do not disclose themselves in headers.

### ForgeTech
Technology fingerprinting engine backed by WhatWeb and response body analysis.
- **What it discovers**: Web servers (Apache, Nginx, IIS), backend runtimes (PHP, Python, Node.js), CMSs (WordPress, Drupal, Joomla), and web applications (e.g. qdPM).
- **Bounded Execution**: Runs with strict execution bounds. If an external technology probe times out, ReconForge outputs `[TIMEOUT] ForgeTech: fingerprinting timed out, continuing` and proceeds without stalling the scan.
- **Accuracy**: Reports confirmed technologies only when supporting evidence is present. Speculative technologies are never promoted to confirmed findings.

### ForgeDiscover
High-speed web content discovery engine backed by Gobuster.
- **What it discovers**: Common web application paths, administration portals, login pages, API endpoints, configuration files, and backups.
- **Dynamic Categories**: Expands wordlist selection at runtime based on confirmed technologies (e.g., adding WordPress paths when WordPress is identified).

### ForgeDiscover-Dir
Directory and content enumeration engine backed by DIRB.
- **Purpose**: Provides secondary directory enumeration to complement Gobuster on structured web targets.

### ForgeTLS
TLS/HTTPS inspection collector.
- **What it discovers**: Certificate subject names, Subject Alternative Names (SAN), issuer authorities, validity windows, and protocol configurations.

### ForgeCore
Normalization, deduplication, and evidence correlation engine.
- **What it does**: Ingests multi-source outputs, removes duplicate URLs, normalizes trailing slashes, merges service records, and correlates endpoints to host identities.
- **Unclassified Classification**: Categorizes unclassified tokens, session cookies, hashes, and secrets with distinct confidence ratings.

### ForgeIntel
Verified vulnerability intelligence backed by the NVD 2.0 API.
- **What it does**: Maps detected product names and exact versions to Common Platform Enumeration (CPE) identifiers and verifies whether the detected version satisfies NVD applicability statements.
- **Zero False-Positive Focus**: If no CVE matches the exact version criteria, ForgeIntel reports `No verified vulnerable CPE matches identified`. ReconForge never guesses CVEs based on product names alone.

---

## Reconnaissance Modes

ReconForge supports two operational reconnaissance modes:

### STANDARD
The primary reconnaissance workflow for comprehensive first-level assessment.
- Scans all 65,535 TCP ports (`-sS -p- -sC -sV -O -A`).
- Executes default NSE discovery scripts and version detection.
- Probes all discovered HTTP/HTTPS services.
- Runs technology fingerprinting and category-aware content discovery.
- Correlates findings against NVD vulnerability intelligence.

### LOW-IMPACT
A reduced-intensity reconnaissance mode designed for sensitive networks or rate-limited environments.
- Scans the top 1,000 TCP ports.
- Avoids aggressive secondary fingerprinting passes.
- Respects rate limits, avoiding rapid request bursts.
- Minimizes request volume while identifying core services and baseline paths.

*(Note: LOW-IMPACT is not an evasion tool and does not claim undetectable stealth.)*

---

## Content Discovery Profiles

ReconForge offers three discovery depth profiles:

### COMMON
**The normal baseline content discovery profile.**
- Contains high-signal paths, common administrative panels, login portals, API endpoints, robots.txt, sitemaps, user portals, configuration files, and backup paths (e.g. `/admin`, `/login`, `/users`, `/secret`, `/timeReport`, `/robots.txt`, `/index.php`).
- Dynamically includes technology-specific categories when applications (such as WordPress, PHP, Apache, or qdPM) are confirmed.

### EXTENDED
Broader path enumeration for targets where COMMON discovery reveals potential hidden structures.
- Adds expanded administration, authentication, configuration, backup, and API endpoint dictionaries.

### DEEP
Exhaustive content discovery profile.
- Employs extensive wordlists across all categories for thorough enumeration during in-depth authorized assessments.

---

## Installation

### Kali Linux / Debian (Recommended)

ReconForge provides an automated one-command installer:

```bash
git clone -b reconforge-intelligence-engine https://github.com/Pennywize-999/ReconForge.git
cd ReconForge
sudo ./install.sh
```

After installation, run ReconForge from anywhere:

```bash
reconforge
```

The installer automatically:
1. Validates the Kali/Debian environment.
2. Installs required system dependencies (`nmap`, `dnsutils`, `whatweb`, `gobuster`, `dirb`, `openssl`).
3. Creates an isolated runtime environment in `/opt/reconforge/venv`.
4. Installs the global `reconforge` command to `/usr/local/bin/reconforge`.
5. Verifies command execution and displays a clean component status table.

---

## Usage and Examples

### Interactive Wizard (Recommended)

Run `reconforge` without arguments to start the interactive scan wizard:

```bash
reconforge
```

**Interactive Prompts:**
1. **Enter IP or URL**: Enter target IP address (e.g. `10.10.10.25`) or URL (e.g. `http://10.10.10.25:80`).
2. **Recon Mode**: Select `1` for **STANDARD** or `2` for **LOW-IMPACT**.
3. **Content Discovery Profile**: Select `1` for **COMMON**, `2` for **EXTENDED**, or `3` for **DEEP**.

ReconForge executes all relevant phases and displays live progress indicators:
```text
PHASE 1 / 5  DISCOVERY
  [>] ForgeDNS: running
  [INFO] ForgeDNS: no DNS record
  [>] ForgeScan: running
  [OK] ForgeScan: completed

SERVICE-AWARE ROUTING
  22/tcp     ssh        OpenSSH 7.9p1 -> inventory only
  80/tcp     http       Apache httpd 2.4.38 -> ForgeProbe -> ForgeTech -> ForgeDiscover

PHASE 2 / 5  SERVICE-AWARE ENUMERATION
  [TARGET] http://10.10.10.25:80
  [>] ForgeProbe: running
  [OK] ForgeProbe: completed
  [>] ForgeTech: running
  [OK] ForgeTech: completed
  TECHNOLOGY INTELLIGENCE
    [OK] Apache 2.4.38
    [OK] PHP 7.3.14
    [OK] qdPM 9.2
  DISCOVERY PROFILE: COMMON
  [>] ForgeDiscover: running
  [OK] ForgeDiscover: completed

PHASE 3 / 5  CONTENT DISCOVERY
  [OK] Service-specific content discovery completed

PHASE 4 / 5  CORRELATION
  [OK] ForgeCore normalization
  [OK] Duplicate findings merged
  [OK] Unclassified intelligence filtered
  [>] ForgeIntel: verifying software versions against NVD
  [OK] ForgeIntel: no verified vulnerable CPE matches

PHASE 5 / 5  REPORT GENERATION
```

### Direct CLI Commands

```bash
# Scan target directly
reconforge 10.10.10.25

# Scan with low-impact mode
reconforge 10.10.10.25 --mode low-impact

# Scan URL target
reconforge -u http://10.10.10.25:8080

# Check tool status
reconforge tools

# View version
reconforge --version
```

---

## Output and Report Structure

ReconForge organizes findings into clear, structured sections:

1. **HOST INFORMATION**: Target IP address, hostnames, MAC address, IPv6, and operating system guesses.
2. **OPEN PORTS / SERVICES**: Discovered open ports, transport protocols, service names, product names, and exact versions.
3. **WEB TECHNOLOGY**: Confirmed server software, frameworks, CMSs, application markers, and frontend libraries.
4. **DISCOVERED / INTERESTING URLS**: Normalized, deduplicated endpoints with HTTP status codes and significance (e.g., `Accessible resource`, `Redirect`, `Protected resource`, `Authentication required`).
5. **TLS / CERTIFICATES**: Subject names, SAN entries, issuers, and validity periods for HTTPS services.
6. **WAF / CDN ANALYSIS**: Detected protection providers, rate-limiting indicators, and status code distributions.
7. **IMPORTANT FINDINGS**: Normalized security observations categorized by severity and confidence.
8. **VULNERABILITY INTELLIGENCE**: Verified CVE records matched by ForgeIntel with CVSS scores and NVD references. If no CVE satisfies exact applicability, displays `No verified vulnerable CPE matches identified`.
9. **UNCLASSIFIED INTELLIGENCE**: Informational artifacts such as session cookies, hashes, and token-like values presented with context and confidence.

---

## Scan Sessions & Saved Results

Every scan creates a unique, durable session in:

```text
~/.reconforge/sessions/session_<timestamp>
```

Each session directory preserves:
- `plan.json`: The executed reconnaissance plan and parameters.
- `target.json`: The fully normalized target data model.
- `report.json`: Machine-readable scan results.
- `report.html`: Standalone interactive HTML report dashboard.
- Raw tool outputs (`nmap.xml`, `headers.txt`, `gobuster.txt`, `whatweb.txt`, execution logs).

The symlink `~/.reconforge/sessions/current` always references the most recent scan.

### Accessing Saved Sessions

```bash
# List all saved sessions
reconforge sessions

# View terminal report of a session
reconforge show current
reconforge show session_2026-08-28_12-00-00_000000

# Export reports
reconforge report current --format html --output report.html
reconforge report current --format json --output report.json
```

---

## Limitations & Responsible Use

- **Authorization Required**: Only run ReconForge against systems you own or have explicit authorization to assess.
- **Verification**: Reconnaissance intelligence aids penetration testers and analysts; findings should be verified during assessment workflows.
- **Version Bounds**: Vulnerability intelligence reports CVEs verified against NVD applicability data; unversioned services cannot be matched automatically.
- **Rate-Limiting**: Web content discovery generates HTTP requests; select the appropriate depth profile (`COMMON`, `EXTENDED`, `DEEP`) based on target scope and engagement rules.

