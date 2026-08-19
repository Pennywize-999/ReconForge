# ReconForge

ReconForge (v0.2.0) is an offline reconnaissance log analyzer and target planning framework for authorized penetration testing environments.

It imports raw outputs from Nmap, Gobuster, and other security tools, normalizing and correlating them. Additionally, it offers an interactive planning mode capable of generating structured execution plans.

**License:** Not yet specified

## Core Capabilities

1. **Offline Analysis:** Import, parse, and analyze existing reconnaissance outputs from various tools.
2. **Target Planning:** Generate intelligent, service-aware tool execution plans for IPs and URLs.
3. **WAF/CDN Analysis:** Detect rate limits, WAFs, and CDNs from offline HTTP headers.

*Important Note on Execution: ReconForge explicitly utilizes a `PlanningOnlyBackend` in this release. It prevents active network execution and only simulates the planning phase to ensure safe operation. No active scanning is performed.*

## Supported Enumeration Sources
- Nmap XML
- DNS, HTTP, SMB, TLS logs
- Gobuster, Dirb, WhatWeb output
- Generic Text Logs

## Installation

See [docs/INSTALLATION.md](docs/INSTALLATION.md) for full setup instructions in a Kali Linux isolated virtual environment (`.venv`).

**Quick Start:**
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
# For development and testing:
python -m pip install -e ".[dev]"
```

## Usage Examples

**Interactive Mode:**
```bash
reconforge
```

**Target Planning:**
```bash
reconforge 10.48.159.132
reconforge -u http://10.48.159.132:5000
```

**Offline Analysis:**
```bash
reconforge analyze tests/fixtures/sample.xml
reconforge import tests/fixtures/
```

**Reports and WAF Analysis:**
```bash
reconforge report current --format html
reconforge waf current
```

**Tool Registry Check:**
```bash
reconforge tools
```

## Documentation

- [User Guide](docs/USER_GUIDE.md): End-to-end workflows and CLI features.
- [Architecture](docs/ARCHITECTURE.md): Component decoupled pipeline and registry design.
- [Installation](docs/INSTALLATION.md): Environment setup and optional external dependencies.
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)
