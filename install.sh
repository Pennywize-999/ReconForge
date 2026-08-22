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
REAL_USER="${SUDO_USER:-${USER}}"

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

echo "[+] Checking operating system"

if [[ ! -f /etc/os-release ]]; then
    echo "[!] Cannot determine operating system."
    exit 1
fi

# Required runtime and reconnaissance utilities used by the current engine.
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

echo "[+] Updating package index"
apt-get update -qq

echo "[+] Checking required system tools"
apt-get install -y "${PACKAGES[@]}"

echo "[OK] System dependencies ready"

echo

echo "[+] Installing ReconForge into ${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"

# Copy the repository into the stable installation location. This keeps the
# executable independent of the directory from which install.sh was called.
if [[ "${SCRIPT_DIR}" != "${INSTALL_DIR}" ]]; then
    rm -rf "${INSTALL_DIR}/app"
    mkdir -p "${INSTALL_DIR}/app"
    cp -a "${SCRIPT_DIR}/." "${INSTALL_DIR}/app/"
else
    mkdir -p "${INSTALL_DIR}/app"
    # If the installer is already inside /opt/reconforge, use the existing tree.
    if [[ ! -f "${INSTALL_DIR}/app/pyproject.toml" ]]; then
        cp -a "${SCRIPT_DIR}/." "${INSTALL_DIR}/app/"
    fi
fi

APP_DIR="${INSTALL_DIR}/app"
python3 -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/python" -m pip install --upgrade pip >/dev/null
"${VENV_DIR}/bin/python" -m pip install "${APP_DIR}"

echo "[+] Creating system command"
ln -sf "${VENV_DIR}/bin/reconforge" "${BIN_PATH}"
chmod 755 "${BIN_PATH}"

# Keep the installation owned by root while allowing the invoking user to run it.
chown -R root:root "${INSTALL_DIR}"

# Basic post-install verification.
echo "[+] Verifying installation"
if ! "${BIN_PATH}" --help >/dev/null 2>&1; then
    echo "[!] ReconForge was installed, but the command verification failed."
    exit 1
fi

# Report availability without failing the installation for optional/missing tools.
echo
printf '%s\n' '--------------------------------------------------------------'
echo "ReconForge dependency status"
printf '%s\n' '--------------------------------------------------------------'
for tool in nmap host whatweb gobuster dirb openssl; do
    if command -v "${tool}" >/dev/null 2>&1; then
        echo "[OK] ${tool}"
    else
        echo "[WARN] ${tool} unavailable"
    fi
done
printf '%s\n' '--------------------------------------------------------------'
echo
printf '%s\n' '[+] ReconForge installation complete.'
echo
printf '%s\n' '    Start ReconForge with:'
printf '%s\n' '        reconforge'
echo
printf '%s\n' '    Installation directory:'
printf '%s\n' "        ${INSTALL_DIR}"
echo