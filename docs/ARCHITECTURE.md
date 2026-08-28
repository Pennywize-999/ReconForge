# SentinelRecon Architecture

SentinelRecon v1.1.1 utilizes a modular, pipeline-driven architecture that coordinates network discovery, service capability classification, web probing, automatic technology fingerprinting, autonomous composite content discovery, normalization, and evidence-based vulnerability intelligence.

```text
Target (IP or URL)
       |
       v
 [1/5] Discovery                <-- DNS & Network Service Discovery (Nmap / Host)
       |
       v
 [2/5] Service Analysis         <-- Capability Classification (AJP, Web, SSH, SMB, DNS, DBs)
       |                            & Evidence Hierarchy Routing (overrides simplistic ports)
       |
       +---> [HTTP Collector]    <-- HTTP Status, Headers & Response Body
       +---> [WhatWeb]           <-- Application & Framework Fingerprinting
       +---> [Tech Classifier]   <-- Automatic Technology & CMS Classification
       +---> [Profile Composer]  <-- Composite Wordlist (COMMON + DETECTED TECHS)
       +---> [Gobuster / Dirb]   <-- Autonomous Multi-Tier Content Discovery
       +---> [TLS Collector]     <-- HTTPS / SSL Certificate Intelligence
       |
       v
 [3/5] Adaptive Enumeration     <-- Specialized multi-protocol enumeration & dynamic triggers
       |
       v
 [4/5] Vulnerability Assessment <-- Authoritative Advisories (Local, NVD 2.0, CISA KEV)
       |                            & Evidence-Based Cross-Service Correlation
       v
 [5/5] Correlation & Reporting  <-- Normalization, Deduplication, & Clean Multi-Format Output
```

## Component Breakdown

### 1. Discovery Subsystem
- Handles DNS forward/reverse resolution and network service discovery.
- In `STANDARD` mode, performs thorough service detection, scripts, and OS identification.
- In `LOW-IMPACT` mode, throttles probe rates and avoids aggressive duplicate requests to respect network and service constraints.

### 2. Service Capability Classifier & Router (`sentinelrecon.services`)
- Classifies services into capabilities: `WEB`, `HTTP`, `HTTPS`, `AJP`, `SSH`, `SMB`, `DNS`, `FTP`, `SMTP`, `SNMP`, `LDAP`, `MYSQL`, `POSTGRESQL`, `REDIS`, `MONGODB`, `GENERIC`.
- Strict evidence priority: Nmap service name $\rightarrow$ Product/version $\rightarrow$ Extra info / banner $\rightarrow$ Active protocol verification $\rightarrow$ Port fallback.
- Detects non-standard ports and protocol contradictions (e.g. 22/tcp HTTP, 80/tcp SSH).
- Prevents calling HTTP directory enumeration tools against non-HTTP services like AJP (e.g. port 8009), SSH (e.g. port 80), SMB, or DNS.

### 3. Autonomous Technology Identification & Profile Composition (`sentinelrecon.core.discovery`)
- **Technology Classifier**: Identifies active application stacks from banners, headers, response body strings, cookies, HTML title, and CPEs (`WORDPRESS`, `TOMCAT`, `APACHE`, `NGINX`, `PHP`, `JOOMLA`, `DRUPAL`, `SPRING`, `LARAVEL`, `DJANGO`, `ASPNET`, `NODE`).
- **Profile Composer**:
  - **Common Baseline is ALWAYS Preserved**: Never replaced by application-specific lists.
  - Automatically merges detected technology profiles (e.g. `COMMON + APACHE + PHP + WORDPRESS` or `COMMON + TOMCAT`).
  - Strict path normalization: deduplicates entries, preserves trailing slashes (`secret/` vs `secret`, `manager/` vs `manager`), preserves file extensions, and retains high-signal paths (`/secret/`, `/backup/`, `/admin/`, `robots.txt`).
- **Bounded Adaptive Queue**: Dynamically enqueues newly detected technology profiles during enumeration if late-stage evidence reveals an unclassified framework.

### 4. Vulnerability Intelligence Subsystem (`sentinelrecon.vulnerability`)
- **Authoritative Datasets**: Structured local dataset for Apache Tomcat, OpenSSH, Apache HTTP Server, etc.
- **Evidence-Based Correlation**: Links multiple service observations on the same host (e.g. Tomcat 9.0.30 on 8080 + AJP connector active on 8009 $\rightarrow$ Ghostcat `CVE-2020-1938`).
- **Clear Confidence & Status**: Distinguishes `POTENTIALLY_VULNERABLE` from `CONFIRMED_VULNERABLE` and includes detailed reasoning, CWE, CVSS, CISA KEV status, and evidence citations.
- **Always Rendered**: Vulnerability Assessment is permanently displayed in Terminal, JSON, and HTML reports, explicitly indicating "Status: No matching vulnerabilities found" when clean.

### 5. Normalization, Sessions & Multi-Format Reporting
- Merges multi-source evidence into a single target data graph (`Target`, `Host`, `Port`, `WebEndpoint`, `Finding`, `Vulnerability`).
- Generates rich Terminal, JSON, and standalone interactive HTML reports.
- Persists all raw outputs, execution plans, models, and generated reports into unique session directories (`~/.sentinelrecon/sessions/session_<timestamp>`) outside the Git repository.
- Filters all internal session paths, temporary directories, and scanner execution metadata from intelligence classification.
