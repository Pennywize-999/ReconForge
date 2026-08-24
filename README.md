# ReconForge

**ReconForge v1.0.0** is a first-level reconnaissance and security-assessment framework for Kali Linux and Unix-like environments. It combines network discovery, DNS intelligence, service-aware enumeration, web technology detection, content discovery, vulnerability intelligence, correlation, and clean reporting into one workflow.

> **Authorized use only.** Use ReconForge only on systems you own or have explicit permission to assess, including authorized penetration tests, CTFs, labs, and security research.

## What ReconForge Does

Give ReconForge an IP address, hostname, or URL. It discovers the target, identifies services, routes service-specific checks automatically, correlates the results, and produces one organized report instead of forcing you to read several separate tool outputs.

The workflow is:

1. **Discovery**: hosts, ports, services, versions, OS hints, CPE data, and DNS information.
2. **Service-aware routing**: select the appropriate modules from what was actually discovered.
3. **Enumeration**: HTTP/HTTPS probing, technology fingerprinting, TLS intelligence, and content discovery.
4. **Correlation**: normalize results and merge duplicates while preserving useful intelligence.
5. **Reporting**: produce clean host, service, URL, finding, vulnerability, and intelligence sections.

ReconForge does not treat every unusual result as a vulnerability. Unverified information is kept separate so it can be investigated without creating false positives.

## ReconForge Modules

| Module | Purpose | Capability |
|---|---|---|
| **ForgeDNS** | DNS and reverse-DNS intelligence | DNS/`host` lookup |
| **ForgeScan** | Port, service, version, OS and CPE discovery | Nmap |
| **ForgeProbe** | HTTP response, headers and bounded body collection | Internal HTTP collector |
| **ForgeTech** | Web technology fingerprinting | WhatWeb plus HTTP application fingerprints |
| **ForgeDiscover** | Web path and file discovery | Gobuster, Dirb and configured discovery modules |
| **ForgeTLS** | HTTPS/TLS and certificate intelligence | Internal TLS collector |
| **ForgeCore** | Normalize, correlate and deduplicate results | ReconForge core |
| **ForgeIntel** | Version-aware vulnerability correlation | ReconForge vulnerability intelligence |
| **ForgeReport** | Clean terminal and HTML reporting | ReconForge reporters |

These are ReconForge's internal module names. They do not claim that the underlying third-party projects have been rewritten.

## ForgeDNS

Collects DNS-related information when applicable:

- Forward DNS resolution
- Reverse DNS information
- Hostname/IP relationships
- DNS errors and unavailable records

A missing DNS/PTR record is reported as an informational result, not as a tool failure. Genuine resolver or execution errors are reported separately, and the rest of the reconnaissance workflow continues.

## ForgeScan

The primary network discovery stage. STANDARD mode performs the complete TCP discovery pass with SYN scanning, default scripts, service/version detection, OS detection and all TCP ports. This is the normal first-level scan, not a reduced scan.

It collects information such as:

- Open ports and states
- Protocols and services
- Product names and versions
- Host status
- MAC address when available
- Hostnames
- OS detection hints
- CPE information when available
- Network distance and related discovery information

ForgeScan drives service-aware routing. For example:

```text
80/tcp  open  http  Apache httpd 2.4.29
          |
          +--> ForgeProbe
          +--> ForgeTech
          +--> ForgeDiscover
```

ReconForge does not blindly run web enumeration against services that are not identified as web services.

## ForgeProbe

Collects HTTP-level information including status codes, headers, final URLs after redirects, content size, cookies, server information, and a bounded response body used for application fingerprinting.

Useful HTTP responses are retained even when they are not `200`. For example, `401`, `403`, `405`, `429`, redirects, and selected server errors can provide useful reconnaissance information.

## ForgeTech

Technology fingerprinting is part of STANDARD reconnaissance. ReconForge uses WhatWeb with bounded timeouts and also inspects the HTTP response body for high-confidence application markers. This allows applications such as qdPM to be identified even when the web server only reports Apache.

Examples of useful technology intelligence include:

- Web server software
- Detected versions
- Frameworks
- CMS indicators
- Application fingerprints
- JavaScript library versions
- Meta-generator information

## ForgeDiscover

Performs web content discovery against applicable HTTP/HTTPS services.

**COMMON means normal first-level reconnaissance.** It is not intentionally limited to only a few obvious paths. Its baseline includes common administration, authentication, API, application, hidden-resource, configuration, backup, user, report and secret-style paths. EXTENDED and DEEP add broader coverage and larger category sets.

Application-specific categories are added when technology intelligence identifies the application. For example, qdPM-specific paths can be added after qdPM is confirmed.

Results from different sources are normalized so the final report does not repeat the same URL several times.

The final report uses full URLs, for example:

| URL | Status | Significance |
|---|---:|---|
| `http://target/` | 200 | Accessible resource |
| `http://target/users` | 200 | Accessible resource |
| `http://target/timeReport` | 200 | Accessible resource |
| `http://target/secret/` | 200 | Accessible resource |
| `http://target/robots.txt` | 200 | Accessible resource |
| `http://target/server-status` | 403 | Protected resource |

## Content Discovery Profiles

ReconForge provides three discovery profiles:

### COMMON

Normal first-level reconnaissance. It includes the expected common web paths, application paths, hidden resources and baseline files without requiring the user to switch to a deeper profile for ordinary coverage.

### EXTENDED

Broader path and file coverage when COMMON does not find enough useful resources.

### DEEP

The largest configured coverage profile. Intended when coverage is more important than scan time and the target is authorized for deeper enumeration.

Wordlists are categorized instead of relying on one uncontrolled giant list. Categories can cover common paths, administration, authentication, APIs, CMS structures, application-specific paths, WordPress paths, backup/configuration names, development/test paths, static assets, and common files/extensions.

## ForgeTLS

Handles HTTPS/TLS-specific collection, including certificate and TLS configuration observations when available.

## ForgeCore

The normalization and correlation layer. It converts different tool outputs into the common ReconForge data model and merges duplicate observations.

For example, if both ForgeProbe and ForgeDiscover find `robots.txt`, the final report can contain one URL rather than two duplicate entries.

ForgeCore also preserves useful information that cannot confidently be classified.

## ForgeIntel and Vulnerability Intelligence

ForgeIntel correlates detected software with vulnerability intelligence.

ReconForge is deliberately conservative. A product name alone is not enough to report a vulnerability.

The intended chain is:

```text
Detected product
      |
Detected version
      |
CPE / product normalization
      |
Vulnerability intelligence lookup
      |
Affected-version applicability check
      |
Verified vulnerability result
```

The system distinguishes between verified matches, insufficient information, and no verified match. A CVE affecting a broad product family is not automatically reported against every installation of that product.

## Unclassified Intelligence

ReconForge can show potentially useful information that cannot yet be confidently classified, including:

- Unknown services
- Unknown HTTP responses
- Unusual response codes
- Identifiers
- Token-like strings
- Hash-like strings
- Encoded-looking values
- Application-specific text
- Unexpected protocol data
- Session cookies, classified separately from encoded/token-like values

These are investigation leads, **not automatic vulnerabilities or credentials**. A session cookie is not automatically treated as a password or encoded credential.

## WAF / CDN Analysis

HTTP observations can be analyzed for indicators associated with WAFs, CDNs, rate limiting, `403`, `429`, and other filtering behavior. Results are presented with confidence because a single `403` does not prove that a WAF exists.

## Persistent Scan Sessions

Every interactive scan is saved automatically. ReconForge creates a unique session directory under:

```text
~/.reconforge/sessions/session_<timestamp>
```

Each completed scan stores the raw tool output, execution logs, plan, normalized target data, JSON report, and HTML report. The latest session is tracked by:

```text
~/.reconforge/sessions/current
```

Useful commands include:

```bash
reconforge sessions
reconforge show <session_id>
reconforge report <session_id> --format html
```

You do **not** need to delete a `sessions/current` directory before every scan. ReconForge creates a new unique session for each run.

## Final Report

The terminal report is organized into separate sections such as:

1. Host information
2. Open ports and services
3. Web technology
4. TLS/certificate information
5. WAF/CDN analysis
6. Discovered / interesting URLs
7. Important findings
8. Vulnerability intelligence
9. Unclassified intelligence

Internal execution evidence is not intended to clutter the user-facing report. The report is designed to show the information needed for reconnaissance rather than raw logs from every underlying tool.

## Supported Tooling

ReconForge currently integrates or recognizes capabilities including:

- **Nmap**: network discovery, service/version detection, OS hints and CPE data
- **DNS/host**: DNS and reverse-DNS lookup
- **Gobuster**: web content discovery
- **Dirb**: web content discovery
- **WhatWeb**: web technology fingerprinting
- **Feroxbuster**: content discovery when installed/configured
- **Internal HTTP collector**: HTTP information collection and application fingerprinting
- **Internal TLS collector**: TLS information collection

ReconForge checks for required external executables before attempting to use them.

## Installation

### Kali Linux, recommended

Clone the project branch and run the installer:

```bash
git clone -b reconforge-intelligence-engine https://github.com/Pennywize-999/ReconForge.git
cd ReconForge
sudo ./install.sh
```

After installation, start ReconForge from anywhere with:

```bash
reconforge
```

The installer handles the Python environment, package installation, required Kali tools, and the global `reconforge` command automatically.

### Update an existing installation

```bash
cd ~/ReconForge
git pull --ff-only origin reconforge-intelligence-engine
sudo ./install.sh
hash -r
reconforge
```

There is no need to remove the previous installation or delete scan sessions. Existing sessions remain under `~/.reconforge/sessions`.

## Quick Start

Run:

```bash
reconforge
```

You will be asked for:

1. Target IP or URL
2. Recon mode
3. Content discovery profile

For a normal complete first-level assessment, select:

```text
STANDARD
COMMON
```

ReconForge then determines which service-aware modules apply to the services it discovers.

Typical flow:

```text
Target
  |
  +--> ForgeDNS
  |
  +--> ForgeScan  (STANDARD: all TCP ports + service/version/OS/scripts)
          |
          +--> HTTP/HTTPS --> ForgeProbe
          |                  ForgeTech
          |                  ForgeDiscover
          |
          +--> HTTPS ------> ForgeTLS
          |
          +--> ForgeCore
                  |
                  +--> ForgeIntel
                  |
                  +--> ForgeReport
```

## Offline Analysis

ReconForge can also analyze existing reconnaissance output when the relevant analysis commands are available.

Supported evidence formats include Nmap XML, DNS output, HTTP output, SMB output, TLS output, Gobuster output, Dirb output, WhatWeb output, and generic text logs.

## Project Structure

```text
ReconForge/
├── reconforge/          Runtime application
│   ├── core/            Models, planning, analysis and vulnerability intelligence
│   ├── execution/       Execution backends
│   ├── parsers/         Reconnaissance parsers
│   ├── reporters/       Terminal and HTML reporting
│   ├── tools/           Tool registry and adapters
│   ├── templates/       Report templates
│   └── wordlists/       Categorized discovery wordlists
├── docs/                User documentation
├── install.sh            Installation helper
├── pyproject.toml        Package configuration
├── reconforge.1          Man page
└── README.md             User documentation
```

## Limitations

ReconForge is a reconnaissance and analysis assistant, not a replacement for expert validation.

- Version detection can be incomplete or inaccurate.
- Vulnerability matching requires sufficient product/version/CPE information.
- Vulnerability databases do not guarantee complete coverage.
- A detected technology does not automatically mean it is vulnerable.
- An unusual string is not automatically a credential or secret.
- WAF/CDN detection is probabilistic.
- Deeper content discovery increases scan time and request volume.
- A path being discovered does not prove that it is exploitable.

Validate important findings before exploitation or formal reporting.

## Responsible Use

Only scan systems for which you have explicit authorization. ReconForge is intended for authorized penetration testing, CTFs, labs, and security research.
