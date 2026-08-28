# ReconForge Architecture

ReconForge v1.0.0 utilizes a modular, pipeline-driven architecture that coordinates network discovery, service identification, web probing, technology fingerprinting, content discovery, normalization, and vulnerability intelligence.

```text
Target (IP or URL)
       |
       v
   [ForgeDNS]          <-- DNS & Reverse-DNS Resolution
       |
       v
   [ForgeScan]         <-- Complete Port & Service Discovery (Nmap)
       |
  (Service-Aware Routing)
       |
       +---> [ForgeProbe]     <-- HTTP Status, Headers & Response Body
       +---> [ForgeTech]      <-- Application & Framework Fingerprinting (WhatWeb)
       +---> [ForgeDiscover]  <-- Category-Driven Content Discovery (Gobuster / Dirb)
       +---> [ForgeTLS]       <-- HTTPS / SSL Certificate Intelligence
       |
       v
   [ForgeCore]         <-- Data Normalization, Deduplication & Model Fusion
       |
       v
   [ForgeIntel]        <-- NVD 2.0 Exact CPE & Version Applicability Matching
       |
       v
 [Terminal / JSON / HTML Report] + [Collision-Safe Session Storage]
```

## Component Breakdown

### 1. ForgeDNS (DNS Intelligence)
- Handles forward name resolution and reverse PTR lookups.
- Normalizes IP-to-hostname mappings.
- Cleanly categorizes normal absence ("no DNS record") vs true resolver errors.

### 2. ForgeScan (Network & Service Discovery)
- Driven by Nmap with explicit configuration per mode.
- In `STANDARD` mode, scans all 65,535 TCP ports (`-sS -p- -sC -sV -O -A`).
- Preserves exact service name, product, version, protocol, port, and state.
- Discovers OS hints and raw CPE strings.

### 3. Service-Aware Routing
- Evaluates discovered open ports from ForgeScan.
- Automatically routes web services (e.g. 80, 443, 8080, 8443, and detected HTTP/HTTPS services) into web intelligence pipelines.
- Prevents sending web enumeration requests to non-web services.

### 4. ForgeProbe (HTTP Service Probing)
- Built-in deterministic HTTP/HTTPS client.
- Collects response codes, headers, redirect chains, server banners, and cookies.
- Captures bounded response bodies for application fingerprinting.

### 5. ForgeTech (Technology Fingerprinting)
- Combines WhatWeb with deep body analysis.
- Identifies CMSs, web frameworks, and application markers (e.g., qdPM, WordPress, jQuery, meta generator tags).
- Employs bounded execution timeouts to prevent scans from stalling.

### 6. ForgeDiscover & ForgeDiscover-Dir (Content Discovery)
- Orchestrates high-speed directory and endpoint discovery (Gobuster / DIRB).
- Category-aware wordlists: admin, authentication, api, backup, configuration, general, and application-specific paths.
- Profiles: `COMMON` (baseline), `EXTENDED` (broad), and `DEEP` (exhaustive).

### 7. ForgeTLS (TLS / HTTPS Inspection)
- Built-in TLS handshake inspection.
- Analyzes SSL/TLS certificate chains, SAN hostnames, issuer authorities, and validity.

### 8. ForgeCore (Normalization & Correlation Engine)
- Merges multi-source evidence into a single target data graph (`Target`, `Host`, `Port`, `WebEndpoint`, `Finding`).
- Deduplicates URLs, normalizes trailing slashes, and resolves conflicting host identities.
- Preserves unclassified intelligence (session cookies, unusual tokens) with distinct confidence ratings.

### 9. ForgeIntel (Vulnerability Intelligence)
- Verifies detected product and version against the National Vulnerability Database (NVD 2.0 API).
- Enforces exact version applicability logic to prevent false positives.
- Prioritizes accuracy over quantity: reports verified CVE matches only when evidence is conclusive.

### 10. Session & Reporting Subsystem
- Persists all raw outputs, execution plans, models, and generated reports into unique session directories (`~/.reconforge/sessions/session_<timestamp>`).
- Dynamic reporting in Terminal, JSON, and standalone HTML formats.

