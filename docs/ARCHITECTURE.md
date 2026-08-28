# SentinelRecon Architecture

SentinelRecon v1.1.0 utilizes a modular, pipeline-driven architecture that coordinates network discovery, service capability classification, web probing, technology fingerprinting, content discovery, normalization, and evidence-based vulnerability intelligence.

```text
Target (IP or URL)
       |
       v
 [1/5] Discovery                <-- DNS & Network Service Discovery (Nmap / Host)
       |
       v
 [2/5] Service Analysis         <-- Capability Classification (AJP, Web, SSH, SMB, DNS, DBs)
       |                            & Adaptive Routing (skips non-HTTP protocols safely)
       |
       +---> [HTTP Collector]    <-- HTTP Status, Headers & Response Body
       +---> [WhatWeb]           <-- Application & Framework Fingerprinting
       +---> [Gobuster / Dirb]   <-- Category-Driven Content Discovery
       +---> [TLS Collector]     <-- HTTPS / SSL Certificate Intelligence
       |
       v
 [3/5] Adaptive Enumeration     <-- Specialized multi-protocol enumeration
       |
       v
 [4/5] Vulnerability Assessment <-- Authoritative Advisories (Local, NVD 2.0, CISA KEV)
       |                            & Evidence-Based Cross-Service Correlation
       v
 [5/5] Correlation & Reporting  <-- Normalization, Deduplication, & Multi-Format Reports
```

## Component Breakdown

### 1. Discovery Subsystem
- Handles DNS forward/reverse resolution and network service discovery.
- In `STANDARD` mode, performs thorough service detection, scripts, and OS identification.
- In `LOW-IMPACT` mode, throttles probe rates to respect network and service constraints.

### 2. Service Capability Classifier & Router (`sentinelrecon.services`)
- Classifies services into capabilities: `HTTP`, `HTTPS`, `AJP`, `SSH`, `SMB`, `DNS`, `FTP`, `SMTP`, `SNMP`, `LDAP`, `MYSQL`, `POSTGRESQL`, `REDIS`, `MONGODB`.
- Prevents calling HTTP directory enumeration tools against non-HTTP services like AJP (e.g. port 8009).
- Accurately reports skipped protocols with clear, technical explanations.

### 3. Web Intelligence & Content Discovery
- Combines native response collectors with WhatWeb and wordlist discovery.
- Category-aware wordlists: admin, authentication, api, backup, configuration, general, and application-specific paths.
- Profiles: `COMMON` (baseline), `MEDIUM` (broad), and `DEEP` (exhaustive).

### 4. Vulnerability Intelligence Subsystem (`sentinelrecon.vulnerability`)
- **Authoritative Datasets**: Structured local dataset for Apache Tomcat, OpenSSH, Apache HTTP Server, etc.
- **Evidence-Based Correlation**: Links multiple service observations on the same host (e.g. Tomcat 9.0.30 on 8080 + AJP connector active on 8009 -> Ghostcat `CVE-2020-1938`).
- **Clear Confidence & Status**: Distinguishes `POTENTIALLY_VULNERABLE` from `CONFIRMED_VULNERABLE` and includes detailed reasoning and evidence citations.
- **Provider Architecture**: Extensible `LocalAdvisoryProvider`, `NVDProvider`, and `KEVProvider`.

### 5. Normalization, Sessions & Multi-Format Reporting
- Merges multi-source evidence into a single target data graph (`Target`, `Host`, `Port`, `WebEndpoint`, `Finding`, `Vulnerability`).
- Generates rich Terminal, JSON, and standalone interactive HTML reports.
- Persists all raw outputs, execution plans, models, and generated reports into unique session directories (`~/.sentinelrecon/sessions/session_<timestamp>`).
