#!/usr/bin/env bash
set -euo pipefail

# ReconForge one-command installer for Kali Linux / Debian systems.
# Usage: sudo ./install.sh

if [[ "${EUID}" -ne 0 ]]; then
    echo "[!] Please run the installer with root privileges:"
    echo "    sudo ./install.sh"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/reconforge"
VENV_DIR="${INSTALL_DIR}/venv"
BIN_PATH="/usr/local/bin/reconforge"

export DEBIAN_FRONTEND=noninteractive

echo
printf '%s\n' '=============================================================='
printf '%s\n' '            RECONFORGE 1.0.0 PRODUCTION INSTALLER             '
printf '%s\n' '=============================================================='
echo

# 1. Environment & OS check
if ! command -v apt-get >/dev/null 2>&1; then
    echo "[!] Unsupported operating system: apt-get package manager required (Kali/Debian)."
    exit 1
fi

if [[ ! -f /etc/os-release ]]; then
    echo "[!] Cannot determine operating system release."
    exit 1
fi

# 2. System packages
SYSTEM_PACKAGES=(
    python3
    python3-pip
    python3-venv
    nmap
    dnsutils
    whatweb
    gobuster
    dirb
    openssl
)

echo "[+] Checking and installing system dependencies..."
apt-get update -qq
apt-get install -y -qq "${SYSTEM_PACKAGES[@]}" >/dev/null
echo "[OK] System dependencies ready."
echo

# 3. Create isolated installation directory & environment
echo "[+] Setting up ReconForge environment in ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}"
rm -rf "${INSTALL_DIR}/app"
mkdir -p "${INSTALL_DIR}/app"
cp -a "${SCRIPT_DIR}/." "${INSTALL_DIR}/app/"

APP_DIR="${INSTALL_DIR}/app"
python3 -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/python" -m pip install --upgrade pip -q >/dev/null 2>&1 || true
"${VENV_DIR}/bin/python" -m pip install -q "${APP_DIR}"

# 4. Create global executable symlink
echo "[+] Configuring global reconforge command..."
ln -sf "${VENV_DIR}/bin/reconforge" "${BIN_PATH}"
chmod 755 "${BIN_PATH}"
chown -R root:root "${INSTALL_DIR}"

# 5. Verification
echo "[+] Verifying installation..."
if ! "${BIN_PATH}" --version >/dev/null 2>&1; then
    echo "[!] ReconForge command verification failed."
    exit 1
fi

echo
printf '%s\n' '--------------------------------------------------------------'
printf '%s\n' 'Component & External Tool Status'
printf '%s\n' '--------------------------------------------------------------'
printf '  %-18s %-20s %s\n' "ReconForge Module" "Underlying Backend" "Status"
printf '%s\n' '  ------------------------------------------------------------'
printf '  %-18s %-20s [OK] Built-in\n' "ForgeProbe" "HTTP/HTTPS Probe"
printf '  %-18s %-20s [OK] Built-in\n' "ForgeCore" "Normalization Engine"
printf '  %-18s %-20s [OK] Built-in\n' "ForgeIntel" "NVD Vulnerability Intel"

EXTERNAL_MODULES=(
    "ForgeScan|Nmap|nmap"
    "ForgeDNS|DNS Utilities|host"
    "ForgeTech|WhatWeb|whatweb"
    "ForgeDiscover|Gobuster|gobuster"
    "ForgeDiscover-Dir|DIRB|dirb"
    "ForgeTLS|OpenSSL|openssl"
)

for entry in "${EXTERNAL_MODULES[@]}"; do
    IFS="|" read -r module tool binary <<< "${entry}"
    if command -v "${binary}" >/dev/null 2>&1; then
        printf '  %-18s %-20s [OK] Ready\n' "${module}" "${tool}"
    else
        printf '  %-18s %-20s [WARN] Missing\n' "${module}" "${tool}"
    fi
done
printf '%s\n' '--------------------------------------------------------------'
echo
echo '[+] ReconForge 1.0.0 installed successfully.'
echo
echo '    Run ReconForge anytime with:'
echo '        reconforge'
echo
echo '    Installation path:'
echo "        ${INSTALL_DIR}"
echo