# ReconForge

**ReconForge v0.2.0** is an authorized reconnaissance and security-assessment framework for Kali Linux and other Unix-like environments. It combines network discovery, DNS intelligence, service-aware enumeration, web technology detection, content discovery, evidence normalization, vulnerability intelligence, and structured reporting into one workflow.

> **Use only on systems you own or have explicit permission to assess.** ReconForge is designed for authorized penetration testing, CTFs, labs, and security research.

---

## What ReconForge Does

ReconForge takes an IP address, hostname, or URL and turns reconnaissance data into a structured assessment.

The workflow is designed around five stages:

1. **Discovery**: identify reachable hosts, ports, services, operating-system hints, and DNS information.
2. **Service-aware routing**: determine which protocol-specific modules are useful for each discovered service.
3. **Enumeration**: inspect HTTP/HTTPS services, technologies, TLS information, and discover interesting web paths.
4. **Correlation**: normalize results, remove duplicates, preserve useful unclassified information, and connect evidence from multiple sources.
5. **Reporting**: present clean host, service, URL, finding, vulnerability, and intelligence results.

ReconForge does not intentionally hide unsuccessful or unusual results. When information cannot be confidently classified, it can be retained as unclassified intelligence instead of silently discarded.

---

# ReconForge Modules

ReconForge gives its internal modules clear names so users can understand the role of each stage without needing to know the underlying command immediately.

| ReconForge Module | Purpose | Underlying capability |
|---|---|---|
| **ForgeDNS** | DNS and reverse-DNS intelligence | DNS lookup / `host` |
| **ForgeScan** | Network discovery, ports, services, OS hints and CPE data | Nmap |
| **ForgeProbe** | HTTP response and header collection | Internal HTTP collector |
| **ForgeTech** | Web technology and server fingerprinting | WhatWeb |
| **ForgeDiscover** | Web content and path discovery | Gobuster, Dirb and configured discovery modules |
| **ForgeTLS** | TLS and certificate intelligence | Internal TLS collector |
| **ForgeCore** | Normalize, correlate and deduplicate reconnaissance data | ReconForge core |
| **ForgeIntel** | Version-aware vulnerability intelligence and correlation | ReconForge vulnerability intelligence |
| **ForgeReport** | Produce the final structured terminal/HTML report | ReconForge reporters |

These names describe ReconForge's role in the workflow. They do **not** claim that the underlying third-party projects have been rewritten or that their upstream licenses have changed.

---

## ForgeDNS

**ForgeDNS** performs DNS-oriented discovery when a hostname or URL provides a DNS-relevant target.

It can collect information such as:

- Forward DNS resolution
- Reverse DNS information where available
- Hostname/IP relationships
- DNS lookup errors and unavailable records

DNS results are fed into the same normalized data model as the rest of the reconnaissance pipeline.

If DNS is unavailable or not applicable, ReconForge records the condition and continues with other discovery modules where possible.

---

## ForgeScan

**ForgeScan** is the primary network discovery stage.

It is responsible for collecting information such as:

- Open TCP ports
- Service names
- Service products
- Service versions
- Protocol information
- Host status
- MAC address when available
- Hostnames
- OS guesses
- CPE information when available
- Network distance and related Nmap discovery information

ReconForge uses the discovered service information to decide what should happen next.

For example:

```text
80/tcp  open  http  Apache httpd 2.4.29
          |
          +--> ForgeProbe
          +--> ForgeTech
          +--> ForgeDiscover
```

This is **service-aware routing**. ReconForge does not blindly run every web module against every target.

---

## ForgeProbe

**ForgeProbe** collects HTTP-level information from discovered HTTP/HTTPS services.

Typical information includes:

- HTTP status codes
- Response headers
- Content length
- Redirects
- Server headers
- Interesting HTTP responses
- Endpoint observations

The results are normalized into ReconForge web endpoint and finding objects.

---

## ForgeTech

**ForgeTech** performs web technology fingerprinting using the WhatWeb capability available on the system.

It can identify information such as:

- Web server software
- Server versions when detected
- Frameworks
- CMS indicators
- Web technologies
- Other fingerprinting plugins reported by WhatWeb

ReconForge separates confirmed technology information from generic metadata so the final report remains readable.

---

## ForgeDiscover

**ForgeDiscover** performs web content discovery against applicable HTTP/HTTPS services.

Depending on the selected discovery profile and installed dependencies, ReconForge can use directory/file enumeration capabilities such as:

- Gobuster
- Dirb
- Additional configured content-discovery tools

The important difference is that ReconForge **normalizes the results** instead of presenting several raw tool outputs separately.

For example, these observations can become one clean table:

| URL | Status | Significance |
|---|---:|---|
| `http://target/` | 200 | Accessible resource |
| `http://target/index.html` | 200 | Accessible resource |
| `http://target/robots.txt` | 200 | Accessible resource |
| `http://target/server-status` | 403 | Protected resource |

Unusual HTTP responses are retained rather than automatically treating every non-200 response as useless. This matters because `401`, `403`, redirects, `405`, `429`, and some server-side errors can reveal useful information during authorized testing.

---

## Content Discovery Profiles

ReconForge includes selectable discovery profiles so the user can balance speed and coverage.

### COMMON

A practical baseline wordlist/profile for normal reconnaissance.

Use this when you want useful coverage without making the scan unnecessarily large.

### EXTENDED

A broader discovery profile intended to find more application paths and files.

Use this when the COMMON profile does not provide enough coverage.

### DEEP

The most comprehensive configured content-discovery profile.

Use this when coverage is more important than scan time and the target is authorized for deeper enumeration.

The project keeps wordlists categorized rather than relying on one enormous undifferentiated list. This allows ReconForge to expand coverage while keeping profiles understandable and maintainable.

---

# Why the Wordlists Are Categorized

ReconForge's content discovery is intended to recognize common application structures, administrative paths, API paths, configuration-related files, CMS paths, backup names, and other frequently encountered resources.

The goal is **not** to throw an arbitrary giant collection of words at every target.

Instead, categories can be combined according to the selected profile. This makes the scan easier to reason about and allows future wordlist improvements without changing the scanner architecture.

Examples of useful categories include:

- General/common paths
- Administrative paths
- Authentication paths
- API paths
- CMS paths
- WordPress-related paths
- Backup/configuration filenames
- Development/test paths
- Static assets
- Common files and extensions

The project should continue to add validated, useful categories over time rather than blindly increasing wordlist size.

---

# ForgeTLS

**ForgeTLS** handles HTTPS/TLS-specific collection.

Depending on the target and available information, it can preserve information about:

- TLS certificates
- Certificate-related findings
- TLS configuration observations
- Certificate names and relationships

TLS findings are kept separate from normal web technology output so the final report remains organized.

---

# ForgeCore

**ForgeCore** is the normalization and correlation layer.

It is responsible for turning different tool outputs into a common ReconForge model.

This is important because the same resource may be discovered by multiple sources. For example, `robots.txt` could be found by both an HTTP collector and a directory enumerator.

Instead of printing duplicate entries, ReconForge can correlate them into a single observation while retaining the source information internally.

ForgeCore also handles unclassified intelligence. Data that does not confidently fit a known category can be retained for review instead of being silently thrown away.

---

# ForgeIntel and Vulnerability Intelligence

**ForgeIntel** handles vulnerability correlation from detected software information.

ReconForge is designed to be conservative here. A product name alone is **not enough** to declare a vulnerability.

The intended workflow is:

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

The report should distinguish between:

- Confirmed vulnerability matches
- Information that could not be verified
- Missing version information
- Products for which no verified match was found

This is important for avoiding false positives. A CVE affecting `Apache 2.x` in general must not automatically be reported against every Apache installation. The detected version and vulnerability applicability must be checked.

When there are no verified matches, the report should clearly say that no verified vulnerable CPE matches were identified rather than inventing a vulnerability result.

---

# Unclassified Intelligence

ReconForge intentionally has a place for information that looks potentially useful but cannot yet be confidently classified.

Examples can include:

- Unknown services
- Unknown HTTP responses
- Unusual response codes
- Unexpected protocol data
- Identifiers
- Token-like strings
- Hash-like strings
- Encoded-looking values
- Application-specific text
- Other unusual observations

These entries are **not automatically vulnerabilities** and should not be treated as credentials merely because they look unusual.

They are presented as investigation leads with context and confidence so the tester can decide whether they matter.

This is especially useful during CTFs and penetration tests where an apparently random string can sometimes turn out to be an application identifier, password, token, hash, or other important artifact.

---

# WAF / CDN Analysis

ReconForge can analyze collected HTTP information for indicators associated with:

- WAF behavior
- CDN indicators
- Rate limiting
- HTTP `403` responses
- HTTP `429` responses
- Other blocking or filtering signals

The result is presented as an analysis with confidence rather than as an unconditional claim. A `403` by itself does not prove that a WAF exists.

---

# Evidence and Reporting

ReconForge keeps machine-readable evidence internally so results can be traced back to their originating collection stage.

The user-facing terminal report is intentionally cleaner than raw tool output.

The final report can contain separate sections for:

1. Host information
2. Open ports and services
3. Web technology
4. TLS/certificate information
5. WAF/CDN analysis
6. Discovered and interesting URLs
7. Important findings
8. Vulnerability intelligence
9. Unclassified intelligence

The **DISCOVERED / INTERESTING URLS** section is presented as a table containing the full URL, HTTP status, and significance.

Example:

```text
DISCOVERED / INTERESTING URLS
------------------------------------------------------------
URL                                      STATUS  SIGNIFICANCE
http://10.0.2.10:80                         200  Accessible resource
http://10.0.2.10:80/index.html              200  Accessible resource
http://10.0.2.10:80/robots.txt              200  Accessible resource
http://10.0.2.10:80/server-status            403  Protected resource
```

Full URLs are preferred over displaying only `/path`, because the protocol, host, and port are important when multiple services are being assessed.

---

# Execution and Safety

ReconForge can be used for planning, offline analysis, and active execution depending on the current project configuration and execution backend.

Active execution invokes locally installed security tools. It does not magically replace those upstream tools with proprietary reimplementations. ReconForge's value is the orchestration, service-aware routing, parsing, normalization, correlation, wordlist profiles, vulnerability intelligence, and reporting around them.

Use active execution only against authorized targets.

Low-impact mode is intended to reduce request volume and behave more conservatively. It is not an anonymity or evasion feature.

---

# Supported Tooling

ReconForge currently integrates or recognizes capabilities including:

- **Nmap**: network discovery, service/version detection, OS hints and CPE data
- **DNS/host**: DNS and reverse-DNS lookup
- **Gobuster**: web content discovery
- **Dirb**: web content discovery
- **WhatWeb**: web technology fingerprinting
- **Feroxbuster**: fast recursive content discovery when installed/configured
- **Internal HTTP collector**: HTTP information collection
- **Internal TLS collector**: TLS information collection

ReconForge checks whether external executables are installed before attempting to use them.

Check available tooling with:

```bash
reconforge tools
```

---

# Installation

On Kali Linux:

```bash
cd ReconForge
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

For development and testing:

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```

---

# Quick Start

Start the interactive workflow:

```bash
reconforge
```

You will be asked for:

1. Target IP or URL
2. Recon mode
3. Content discovery profile

ReconForge then determines which modules apply to the discovered services.

A typical HTTP workflow looks like:

```text
Target
  |
  +--> ForgeDNS
  |
  +--> ForgeScan
          |
          +--> 80/tcp HTTP
                  |
                  +--> ForgeProbe
                  +--> ForgeTech
                  +--> ForgeDiscover
          |
          +--> ForgeTLS for HTTPS
          |
          +--> ForgeCore
                  |
                  +--> ForgeIntel
                  |
                  +--> ForgeReport
```

---

# Offline Analysis

ReconForge can also analyze existing reconnaissance output without performing a new scan.

Examples:

```bash
reconforge analyze tests/fixtures/sample.xml
reconforge import tests/fixtures/
```

Supported evidence includes:

- Nmap XML
- DNS output
- HTTP output
- SMB output
- TLS output
- Gobuster output
- Dirb output
- WhatWeb output
- Generic text logs

This allows reconnaissance to be collected separately and analyzed later.

---

# Reports

Generate an HTML report where supported:

```bash
reconforge report current --format html
```

WAF/CDN analysis can be displayed with:

```bash
reconforge waf current
```

---

# Project Structure

```text
ReconForge/
├── reconforge/
│   ├── core/          Core models, planning, analysis and vulnerability intelligence
│   ├── execution/     Execution backends
│   ├── parsers/       Reconnaissance output parsers
│   ├── reporters/     Terminal and HTML reporting
│   ├── tools/         Tool registry and adapters
│   ├── templates/     Report templates
│   └── wordlists/     Categorized content-discovery wordlists
├── tests/             Automated tests and fixtures
├── docs/              Extended documentation
├── install.sh         Installation helper
├── pyproject.toml     Python package configuration
└── README.md          Project overview
```

---

# Development Quality

Before submitting changes, run:

```bash
python -m pytest -q
```

Changes should not silently remove information from reconnaissance results. Parser changes, routing changes, vulnerability matching changes, and report changes should include or update tests where appropriate.

---

# Limitations

ReconForge is an orchestration and analysis framework, not a replacement for expert judgment.

Important limitations include:

- Tool output quality depends partly on the underlying tools and target behavior.
- Version detection can be incomplete or inaccurate.
- Vulnerability matching requires sufficient product/version/CPE information.
- No vulnerability database can guarantee complete coverage.
- A detected technology does not automatically mean it is vulnerable.
- An unusual string is not automatically a credential or secret.
- WAF/CDN detection is probabilistic and should be treated as an indicator.
- Deeper content discovery can increase scan time and request volume.

ReconForge should therefore be used as a structured reconnaissance assistant, with findings manually validated before exploitation or reporting.

---

# Security and Responsible Use

Only scan systems for which you have explicit authorization.

For security issues in ReconForge itself, see `SECURITY.md`.

---

# Documentation

- [User Guide](docs/USER_GUIDE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Installation](docs/INSTALLATION.md)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)

**License:** Not yet specified.
