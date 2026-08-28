# Installation Guide

SentinelRecon is built for Kali Linux, Debian, and Linux-based security distributions. The automated installer sets up an isolated environment, installs system dependencies, registers the `sentinelrecon` command globally (with `reconforge` compatibility alias), and verifies component readiness.

## Recommended Kali Installation

Run the one-command installer:

```bash
git clone -b reconforge-intelligence-engine https://github.com/Pennywize-999/ReconForge.git
cd ReconForge
sudo ./install.sh
```

After installation completes, start SentinelRecon from any directory:

```bash
sentinelrecon
```

*(Note: `reconforge` also works as a compatibility alias)*

## What the Installer Does

1. **Verifies Environment**: Validates that the system is a supported Linux distribution with `apt-get`.
2. **Installs System Dependencies**: Checks and installs required system utilities:
   - `python3`, `python3-pip`, `python3-venv`
   - `nmap` (Network discovery and service identification)
   - `dnsutils` (DNS resolution and reverse lookups)
   - `whatweb` (Web technology fingerprinting)
   - `gobuster` (High-speed content discovery)
   - `dirb` (Directory and content enumeration)
   - `openssl` (TLS/SSL certificate analysis)
3. **Creates Isolated Runtime**: Installs SentinelRecon into `/opt/sentinelrecon/venv` to keep system Python packages clean and compliant with PEP 668.
4. **Installs Global Executables**: Symlinks the primary command `/usr/local/bin/sentinelrecon` and legacy alias `/usr/local/bin/reconforge`.
5. **Verifies Components**: Runs self-tests to ensure CLI commands and capabilities are operational.

## Updating SentinelRecon

To update an existing installation:

```bash
cd ReconForge
git pull --ff-only origin reconforge-intelligence-engine
sudo ./install.sh
```

Existing scan sessions in `~/.sentinelrecon/sessions/` and `~/.reconforge/sessions/` are preserved during updates.
