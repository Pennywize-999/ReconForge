#!/usr/bin/env bash
set -euo pipefail

# ReconForge one-command installer for Kali/Debian systems.
# Usage: sudo ./install.sh

if [[ "${EUID}" -ne 0 ]]; then
    echo "[!] Please run the installer with sudo:"
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
printf '%s\n' '                    RECONFORGE INSTALLER                     '
printf '%s\n' '=============================================================='
echo

if ! command -v apt-get >/dev/null 2>&1; then
    echo "[!] This installer currently supports Kali/Debian systems."
    exit 1
fi

if [[ ! -f /etc/os-release ]]; then
    echo "[!] Cannot determine operating system."
    exit 1
fi

PACKAGES=(
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

echo "[+] Checking system requirements"
apt-get update -qq
apt-get install -y "${PACKAGES[@]}"
echo "[OK] System requirements ready"
echo

echo "[+] Installing ReconForge into ${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"
rm -rf "${INSTALL_DIR}/app"
mkdir -p "${INSTALL_DIR}/app"
cp -a "${SCRIPT_DIR}/." "${INSTALL_DIR}/app/"

APP_DIR="${INSTALL_DIR}/app"
python3 -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/python" -m pip install --upgrade pip >/dev/null
"${VENV_DIR}/bin/python" -m pip install "${APP_DIR}"

echo "[+] Creating ReconForge command"
ln -sf "${VENV_DIR}/bin/reconforge" "${BIN_PATH}"
chmod 755 "${BIN_PATH}"
chown -R root:root "${INSTALL_DIR}"

echo "[+] Verifying installation"
if ! "${BIN_PATH}" --help >/dev/null 2>&1; then
    echo "[!] ReconForge installation verification failed."
    exit 1
fi

echo
echo '--------------------------------------------------------------'
echo 'ReconForge module status'
echo '--------------------------------------------------------------'
MODULES=(
    "ForgeScan|nmap"
    "ForgeDNS|host"
    "ForgeTech|whatweb"
    "ForgeDiscover|gobuster"
    "ForgeDiscover-Dir|dirb"
    "ForgeTLS|openssl"
)
for entry in "${MODULES[@]}"; do
    module="${entry%%|*}"
    binary="${entry##*|}"
    if command -v "${binary}" >/dev/null 2>&1; then
        printf '[OK] %-20s ready\n' "${module}"
    else
        printf '[WARN] %-20s unavailable\n' "${module}"
    fi
done
echo '--------------------------------------------------------------'
echo
echo '[+] ReconForge installation complete.'
echo
echo '    Start ReconForge with:'
echo '        reconforge'
echo
echo '    Installation directory:'
echo "        ${INSTALL_DIR}"
echo