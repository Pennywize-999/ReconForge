# Installation Guide

ReconForge is designed to run in isolated virtual environments on modern Kali Linux systems.

## Prerequisites

- Python 3.8+
- Kali Linux (or similar Debian-based security distribution)

## Virtual Environment Setup (PEP 668)

Modern Kali Linux environments restrict global `pip` installations to prevent system conflicts (PEP 668). You must install ReconForge within a virtual environment.

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## Standard Installation

```bash
# Clone the repository
git clone https://github.com/Pennywize-999/ReconForge
cd ReconForge

# Ensure your venv is activated, then install:
python -m pip install -e .
```

## Development and Testing Installation

If you intend to run tests or develop, install the development dependencies:

```bash
python -m pip install -e ".[dev]"
```
*(Note: `pytest` is explicitly a development dependency and is installed via the `[dev]` extra.)*

## External Tool Dependencies (Optional)

ReconForge v0.2.0 uses a **PlanningOnlyBackend** and performs offline analysis. It does NOT actively execute network scans.
However, for future execution-layer integrations or if you plan to manually generate outputs for the parsers, the following underlying OS security tools are recommended:

```bash
sudo apt update
sudo apt install nmap gobuster dirb whatweb
```

## Updating

To update ReconForge:
```bash
git pull origin main
python -m pip install -e .
```
