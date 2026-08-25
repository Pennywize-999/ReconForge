#!/bin/bash
set -e

echo "[*] Installing ReconForge offline analyzer..."

# Ensure python3-pip and venv are installed (Kali/Debian based)
if command -v apt-get &> /dev/null; then
    echo "[*] Checking for python3-pip and python3-venv..."
    sudo apt-get update -qq
    sudo apt-get install -y python3-pip python3-venv
fi

echo "[*] Creating virtual environment in /opt/reconforge..."
sudo mkdir -p /opt/reconforge
sudo chown -R $USER:$USER /opt/reconforge
if [ ! -d "/opt/reconforge/venv" ]; then
    python3 -m venv /opt/reconforge/venv
fi

echo "[*] Installing requirements and package..."
source /opt/reconforge/venv/bin/activate
pip install -e .

echo "[*] Creating symlink in /usr/local/bin/reconforge..."
sudo ln -sf /opt/reconforge/venv/bin/reconforge /usr/local/bin/reconforge

echo "[+] Installation complete! You can now run 'reconforge'"

