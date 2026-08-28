# SentinelRecon

**SentinelRecon** is an adaptive reconnaissance and evidence correlation engine designed for authorized penetration testing, security audits, CTF challenges, and laboratory assessments. It coordinates host and network discovery, service capability classification, web technology fingerprinting, autonomous content discovery, and evidence-based vulnerability intelligence into a unified, reliable workflow.

> [!NOTE]
> **Authorized Use Only**: SentinelRecon is strictly engineered for authorized penetration testing, professional security assessments, and lab environments. Always obtain explicit written authorization before scanning target systems. SentinelRecon executes zero offensive exploit payloads.

---

## Key Capabilities

- **Adaptive 5-Stage Reconnaissance Pipeline**:
  - `[1/5] Discovery`: Network and DNS service discovery.
  - `[2/5] Service Analysis`: Protocol classification and intelligent capability routing.
  - `[3/5] Adaptive Enumeration`: Autonomous web probing, technology fingerprinting, and composite content discovery.
  - `[4/5] Vulnerability Assessment`: Evidence-based vulnerability intelligence and cross-service correlation.
  - `[5/5] Findings Correlation & Reporting`: Data fusion, deduplication, and multi-format report generation.
- **Service Capability Classification (`sentinelrecon.services`)**: Classifies services into distinct capabilities (`HTTP`, `HTTPS`, `AJP`, `SSH`, `SMB`, `DNS`, `FTP`, `SMTP`, `SNMP`, `LDAP`, `MYSQL`, `POSTGRESQL`, `REDIS`, `MONGODB`). Distinguishes non-HTTP protocols (e.g. AJP13 on port 8009, SSH on port 80) to avoid sending invalid HTTP path requests.
- **Autonomous Discovery Engine**:
  - **Common Baseline is ALWAYS Preserved**: Never substituted or removed.
  - **Automatic Technology Composition**: Merges curated datasets for detected technologies (WordPress, Tomcat, Apache, Nginx, PHP, Joomla, Drupal, Spring, Django, Laravel, ASP.NET, Node.js).
  - **Strict Path Normalization**: Deduplicates entries while strictly preserving trailing-slash directory semantics (`secret/` vs `secret`, `manager/` vs `manager`) and file extensions.
  - **High-Signal Path Retention**: Always retains sensitive paths (`/secret/`, `/backup/`, `/admin/`, `robots.txt`, `sitemap.xml`, `.env`, `.git/`).
- **Evidence-Based Vulnerability Intelligence (`sentinelrecon.vulnerability`)**:
  - Authoritative local knowledge base (Tomcat Ghostcat, DoS, Deserialization, CGI, PUT JSP RCE, OpenSSH regreSSHion, Apache HTTP Server path traversal).
  - Cross-service correlation linking multi-port observations on the same host (e.g., Tomcat HTTP service on 8080 + active AJP connector on 8009 for `CVE-2020-1938`).
  - Clear distinction between `POTENTIALLY_VULNERABLE` (version in affected range and prerequisites met) and `CONFIRMED_VULNERABLE`.
  - Integration with NIST NVD 2.0 and CISA Known Exploited Vulnerabilities (KEV) catalog.
- **Robust Version Normalization & Matcher**: Accurately parses complex version strings (`9.0.30`, `9.0.0.M1`, `7.2p2 Ubuntu 4ubuntu2.8`, Debian package suffixes) with explicit notes on vendor security backport uncertainty.
- **Clean Capability Abstraction**: Terminal and user-facing reports focus on application capabilities (`Network Service Discovery`, `Web Content Discovery`, `Technology Fingerprinting`) while maintaining underlying tool provider references internally.
- **Durable, Collision-Safe Session Storage**: Saves raw tool outputs, execution logs, and normalized models under `~/.sentinelrecon/sessions/session_<timestamp>`.
- **Multi-Format Reporting**: Generates interactive terminal summaries, structured JSON data, and standalone HTML reports without leaking internal scanner execution paths.
- **Backward Compatibility**: Full backward compatibility for stored sessions and a seamless `reconforge` CLI command alias.

---

## Architecture Overview

```text
                     Target (IP or URL)
                             |
                             v
                     [1/5] DISCOVERY          <-- Network Discovery & DNS Resolution
                             |
                             v
                  [2/5] SERVICE ANALYSIS      <-- Service Capability Classification
                             |                    (AJP, Web, SSH, SMB, DNS, DBs)
                             |
             +---------------+---------------+
             |                               |
             v                               v
     [HTTP / HTTPS]                    [Non-HTTP / AJP / SSH]
     (Probe -> Tech -> Discover)       (Service Intelligence)
             |                               |
             +---------------+---------------+
                             |
                             v
                [3/5] ADAPTIVE ENUMERATION   <-- Autonomous Multi-Protocol Enumeration
                             |
                             v
              [4/5] VULNERABILITY ASSESSMENT <-- Local Advisories, NVD, CISA KEV
                             |                   & Cross-Service Correlation
                             v
              [5/5] CORRELATION & REPORTING  <-- Data Fusion & Clean Multi-Format Output
                             |
                             v
               [Terminal / JSON / HTML Report]
```

---

## Installation

### Kali Linux & Debian Quick Install

```bash
git clone -b reconforge-intelligence-engine https://github.com/Pennywize-999/ReconForge.git
cd ReconForge
sudo ./install.sh
```

The installer configures an isolated Python virtual environment at `/opt/sentinelrecon/venv` and symlinks the global commands `/usr/local/bin/sentinelrecon` and `/usr/local/bin/reconforge`.

---

## Quick Start & Usage

### Interactive Wizard

Running `sentinelrecon` (or legacy alias `reconforge`) without arguments launches the streamlined interactive workflow:

```bash
sentinelrecon
```

Prompts in order:
1. **Target**: IP address, hostname, or full HTTP/HTTPS URL.
2. **Recon Mode**:
   - `1. Standard Recon`: Comprehensive authorized reconnaissance.
   - `2. Low-Impact Recon`: WAF/Firewall-conscious, rate-limited reconnaissance.

*All service and technology-specific discovery profiles are automatically selected, composed, and executed based on detected evidence.*

### Direct Command-Line Scanning

```bash
# Scan an IP target directly
sentinelrecon 10.49.128.206

# Scan with Low-Impact mode
sentinelrecon 10.10.10.25 --mode low-impact

# Scan a specific web service URL
sentinelrecon -u http://10.49.128.206:8080

# Scan an HTTPS service URL with custom port
sentinelrecon -u https://target.example.com:8443

# Generate offline execution plan without running tools
sentinelrecon 10.49.128.206 --plan
```

---

## Session & Report Management

Every scan creates a timestamped session in `~/.sentinelrecon/sessions/`.

```bash
# List all saved sessions
sentinelrecon sessions

# Display terminal report of latest scan
sentinelrecon show current

# Export reports to JSON or HTML
sentinelrecon report current --format json --output report.json
sentinelrecon report current --format html --output report.html

# View WAF / CDN analysis for a session
sentinelrecon waf current

# Check capability and provider readiness
sentinelrecon tools
```

---

## Offline Analysis & Ingestion

Ingest outputs from external tools or previous engagements:

```bash
# Ingest and analyze a directory of scan outputs
sentinelrecon import /path/to/logs/

# Analyze a single output file
sentinelrecon analyze /path/to/nmap.xml
```

---

## Vulnerability Intelligence & Correlation

SentinelRecon enforces strict evidence-based correlation:
- **No Speculative CVEs**: Vulnerabilities are only reported when detected versions fall within verified affected ranges.
- **Cross-Service Verification**: Multi-service prerequisites (such as Apache Tomcat requiring an active AJP connector for `CVE-2020-1938`) are correlated directly across open ports.
- **Transparent Status**: Reports indicate `POTENTIALLY_VULNERABLE` with detailed reasoning and multi-source evidence.
- **Distro Backport Awareness**: Explicitly highlights when distribution package suffixes (e.g. `Ubuntu 4ubuntu2.8`) mean vendor backport patch status cannot be confirmed offline.

---

## License

SentinelRecon is released under the [MIT License](LICENSE).
