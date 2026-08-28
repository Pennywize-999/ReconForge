# SentinelRecon User Guide

SentinelRecon v1.1.1 is an adaptive reconnaissance and evidence correlation engine designed for authorized penetration testing, security audits, and laboratory environments.

---

## 1. CLI Reference

- `sentinelrecon`: Launches the interactive reconnaissance wizard.
- `sentinelrecon --help`: Displays the help menu and available commands.
- `sentinelrecon --version`: Displays the installed version (v1.1.1).
- `sentinelrecon tools`: Displays capability provider status.

*(Note: The legacy command `reconforge` is available as a backward-compatible alias)*

### Command-Line Arguments & Direct Scanning

```bash
# Scan an IP address directly (STANDARD mode)
sentinelrecon 10.49.128.206

# Scan with LOW-IMPACT reconnaissance mode
sentinelrecon 10.10.10.25 --mode low-impact

# Scan a specific HTTP service URL
sentinelrecon -u http://10.49.128.206:8080

# Scan an HTTPS service URL with custom port
sentinelrecon -u https://target.example.com:8443 --mode low-impact

# Generate offline execution plan without executing tools
sentinelrecon 10.49.128.206 --plan
```

### Interactive Wizard Workflow

Running `sentinelrecon` without arguments presents the streamlined interactive workflow:

1. **Target Input**:
   - Enter IP address, hostname, or full HTTP/HTTPS URL.
   - (For HTTP/HTTPS targets without an explicit port, prompts for Default vs Custom port).
2. **Recon Mode**:
   - `1. Standard Recon`: Full comprehensive reconnaissance (port scanning, service detection, OS identification, web probing, technology fingerprinting, autonomous content discovery, and evidence-based vulnerability intelligence).
   - `2. Low-Impact Recon`: WAF/Firewall-conscious reconnaissance (rate-limited, respects Retry-After, avoids aggressive duplicate requests).

> [!NOTE]
> Discovery datasets (WordPress, Tomcat, Apache, Nginx, PHP, Spring, Django, Laravel, etc.) are **automatically classified, composed, and executed** with the Common baseline based on evidence.

---

## 2. Autonomous Technology Discovery & Profile Composition

SentinelRecon enforces deterministic composite wordlist generation:
- **Common Baseline is ALWAYS Preserved**: The baseline wordlist is never replaced by framework-specific lists.
- **Automatic Fusion**: When technologies like Apache, PHP, and WordPress are detected, SentinelRecon generates a composite candidate set (`COMMON + APACHE + PHP + WORDPRESS`).
- **High-Signal Paths**: Important target findings like `/secret/`, `/backup/`, `/admin/`, and `robots.txt` are strictly retained.
- **Trailing Slashes**: Distinctions between directories (`secret/`, `manager/`, `wp-admin/`) and files (`secret`, `manager`, `wp-login.php`) are preserved.

---

## 3. Session Management & Reports

Every scan creates a unique, collision-safe session under `~/.sentinelrecon/sessions/session_<timestamp>`. Previous scans are never overwritten.

### Managing Sessions

```bash
# List all saved sessions
sentinelrecon sessions

# View terminal report of a session (or current for latest)
sentinelrecon show current
sentinelrecon show session_2026-08-28_12-00-00

# Export reports in different formats
sentinelrecon report current --format terminal
sentinelrecon report current --format json --output scan.json
sentinelrecon report current --format html --output scan.html

# View WAF / CDN analysis for a session
sentinelrecon waf current
```
