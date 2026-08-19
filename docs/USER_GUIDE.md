# ReconForge User Guide

ReconForge (v0.2.0) is an offline reconnaissance log analyzer designed for authorized penetration testing environments.
It analyzes previously generated reconnaissance data (like Nmap, Gobuster, WhatWeb) and plans structured reconnaissance workflows.
**Note:** ReconForge does not currently execute network scanning tools itself. It relies on a `PlanningOnlyBackend` to safely generate execution plans without performing active network requests.

## 1. CLI Reference

- `reconforge --help`: Displays the help menu and available commands.
- `reconforge --version`: Displays the installed ReconForge version (v0.2.0).
- `reconforge --test`: Runs the built-in testing workflow.

### Target Planning & Interactive Mode

ReconForge can plan reconnaissance for an IP or URL.

- **Interactive Mode**: Run `reconforge` with no arguments to start the interactive wizard.
  1. Select Mode: `Standard Recon` or `WAF-Aware Low-Impact Recon`.
  2. Select Target Type: `IP Address` or `URL`.
  3. (If URL) Select Port Configuration: `Default Port` or `Custom Port`.

- **Direct Target Execution**:
  - `reconforge 10.48.159.132`
  - `reconforge -u http://10.48.159.132:5000` (or `--url`)

**Target Normalization**:
When you provide `http://10.48.159.132:5000`, ReconForge automatically normalizes the target:
- `scheme = http`
- `host = 10.48.159.132`
- `ip = 10.48.159.132`
- `port = 5000`

### Execution Modes

- `--mode standard`: Standard execution planning utilizing all applicable tools aggressively.
- `--mode low-impact`: **WAF-Aware Low-Impact Recon**. A conservative, rate-limit-aware planning mode. It does NOT bypass WAFs or security controls. Instead, it respects `Retry-After` headers, spaces out requests, and minimizes repetitive or evasive actions to analyze environments safely.

### Offline Analysis Workflow

You can import and analyze existing reconnaissance outputs:
1. `reconforge import <directory>`: Imports an entire directory of logs/results into a new session.
2. `reconforge analyze <file>`: Analyzes a single file and correlates it.

**Intended Workflow:**
1. Existing reconnaissance output (e.g., Nmap XML, Gobuster TXT)
2. `reconforge import` or `analyze`
3. Parsers extract the raw data
4. Normalized models (`ReconTarget`) are populated
5. Correlation connects IP and Web services
6. Vulnerability intelligence cross-references CPEs/CVEs
7. WAF analysis detects rate limits or CDN presence
8. Session state is updated
9. Terminal / JSON / HTML report is generated

### Sessions

- `reconforge sessions`: Lists all historical sessions stored in the internal database.
- `reconforge show <id>`: Shows a quick summary of a specific session (use `current` for the latest session).

### Reports

Generate rich reports from a session:
- `reconforge report <id>` (Defaults to terminal)
- `reconforge report <id> --format terminal`
- `reconforge report <id> --format json`
- `reconforge report <id> --format html`

### WAF Analysis

- `reconforge waf <id>`: Outputs the WAF and CDN analysis for the specified session (use `current` for the latest session), detailing rate-limit indicators and detected protection headers.

### Tool Registry

- `reconforge tools`: Displays the internal tool registry, listing which execution tool adapters (e.g., Nmap, Gobuster) are currently available on the system.
