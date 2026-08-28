# Installation Guide

ReconForge is built for Kali Linux and Debian-based security distributions. The automated installer sets up an isolated environment, installs system dependencies, registers the `reconforge` command globally, and verifies component readiness.

## Recommended Kali Installation

Run the one-command installer:

```bash
git clone -b reconforge-intelligence-engine https://github.com/Pennywize-999/ReconForge.git
cd ReconForge
sudo ./install.sh
```

After installation completes, start ReconForge from any directory:

```bash
reconforge
```

## What the Installer Does

1. **Verifies Environment**: Validates that the system is a supported Linux distribution with `apt-get`.
2. **Installs System Dependencies**: Checks and installs missing system utilities:
   - `python3`, `python3-pip`, `python3-venv`
   - `nmap` (Network discovery and service identification)
   - `dnsutils` (DNS resolution and reverse lookups)
   - `whatweb` (Web technology fingerprinting)
   - `gobuster` (High-speed content discovery)
   - `dirb` (Directory and content enumeration)
   - `openssl` (TLS/SSL certificate analysis)
3. **Creates Isolated Runtime**: Installs ReconForge into `/opt/reconforge/venv` to keep system Python packages clean and compliant with PEP 668.
4. **Installs Global Executable**: Symlinks the binary to `/usr/local/bin/reconforge`.
5. **Verifies Components**: Runs self-tests to ensure CLI commands and tools are operational.

## Updating ReconForge

To update an existing installation:

```bash
cd ReconForge
git pull --ff-only origin reconforge-intelligence-engine
sudo ./install.sh
```

Existing scan sessions in `~/.reconforge/sessions/` are preserved during updates.

