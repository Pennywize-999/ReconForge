"""Production regression tests for SentinelRecon v1.1.1 corrections."""

import json
import os
import tempfile
from io import StringIO
from unittest.mock import patch

import pytest
from rich.console import Console

import sentinelrecon
import reconforge
from sentinelrecon.core.analyzer import Analyzer
from sentinelrecon.core.models import (
    Confidence,
    Finding,
    FindingType,
    Host,
    ModelEncoder,
    Port,
    ReconPlan,
    ReconTarget,
    ScanSession,
    Service,
    Target,
    Vulnerability,
)
from sentinelrecon.core.planner import ReconPlanner
from sentinelrecon.core.session import SessionManager
from sentinelrecon.core.target_parser import TargetParser
from sentinelrecon.execution.backend import RealExecutionBackend
from sentinelrecon.reporters.html import HTMLReporter
from sentinelrecon.reporters.json_ext import JSONReporter
from sentinelrecon.reporters.terminal import TerminalReporter
from sentinelrecon.services.classifier import (
    ServiceCapability,
    ServiceCertainty,
    ServiceClassifier,
    ServiceIdentity,
)
from sentinelrecon.services.router import ServiceCapabilityRouter
from sentinelrecon.vulnerability.engine import VulnerabilityEngine
from sentinelrecon.vulnerability.models import AssessmentStatus


# ---------------------------------------------------------------------------
# 1. HTTP service on non-standard port (e.g. 22/tcp HTTP Apache httpd)
# ---------------------------------------------------------------------------
def test_http_on_non_standard_port_22():
    classifier = ServiceClassifier()
    p = Port(
        number=22,
        protocol="tcp",
        state="open",
        service=Service(name="http", product="Apache httpd", version="2.4.10"),
    )
    ident = classifier.classify(p)
    assert ident.is_web is True
    assert ident.capability == ServiceCapability.WEB
    assert ident.is_ssh is False
    assert ident.confidence == Confidence.HIGH
    assert ident.contradiction is not None
    assert "22" in ident.contradiction


# ---------------------------------------------------------------------------
# 2. SSH service on non-standard port (e.g. 80/tcp SSH OpenSSH)
# ---------------------------------------------------------------------------
def test_ssh_on_non_standard_port_80():
    classifier = ServiceClassifier()
    p = Port(
        number=80,
        protocol="tcp",
        state="open",
        service=Service(name="ssh", product="OpenSSH", version="6.7p1"),
    )
    ident = classifier.classify(p)
    assert ident.is_ssh is True
    assert ident.is_web is False
    assert ident.capability == ServiceCapability.SSH
    assert ident.confidence == Confidence.HIGH
    assert ident.contradiction is not None
    assert "80" in ident.contradiction


# ---------------------------------------------------------------------------
# 3. Contradictory Nmap service/port combinations
# ---------------------------------------------------------------------------
def test_contradictory_nmap_service_routing():
    router = ServiceCapabilityRouter()
    p_ssh_on_80 = Port(
        number=80,
        protocol="tcp",
        state="open",
        service=Service(name="ssh", product="OpenSSH", version="6.7p1"),
    )
    skip, reason = router.should_skip_web_enumeration(p_ssh_on_80)
    assert skip is True
    assert "SSH is not an HTTP service" in reason

    p_http_on_22 = Port(
        number=22,
        protocol="tcp",
        state="open",
        service=Service(name="http", product="Apache httpd", version="2.4.10"),
    )
    skip_http, _ = router.should_skip_web_enumeration(p_http_on_22)
    assert skip_http is False


# ---------------------------------------------------------------------------
# 4 & 10. AJP 8009 + Tomcat 8080 Ghostcat correlation
# ---------------------------------------------------------------------------
def test_ajp_tomcat_ghostcat_correlation():
    host = Host(ip="10.49.128.206", status="up")
    host.ports.append(
        Port(
            number=8009,
            protocol="tcp",
            state="open",
            service=Service(name="ajp13", product="Apache Jserv", version="1.3"),
        )
    )
    host.ports.append(
        Port(
            number=8080,
            protocol="tcp",
            state="open",
            service=Service(name="http", product="Apache Tomcat", version="9.0.30"),
        )
    )
    target = Target(hosts={host.ip: host})

    engine = VulnerabilityEngine()
    count = engine.assess_target(target)
    assert count >= 1

    ghostcat = next((v for v in host.vulnerabilities if v.cve_id == "CVE-2020-1938"), None)
    assert ghostcat is not None
    assert ghostcat.severity == "CRITICAL"
    assert ghostcat.cvss == 9.8
    assert ghostcat.kev_status is True
    assert ghostcat.confidence in (Confidence.HIGH, Confidence.CONFIRMED)


# ---------------------------------------------------------------------------
# 5. Non-HTTP service must not receive HTTP directory enumeration
# ---------------------------------------------------------------------------
def test_non_http_services_skipped_in_web_discovery():
    target = Target()
    host = Host(ip="10.49.160.134", status="up")
    host.ports.append(
        Port(number=80, protocol="tcp", state="open", service=Service(name="ssh", product="OpenSSH"))
    )
    host.ports.append(
        Port(number=8009, protocol="tcp", state="open", service=Service(name="ajp13", product="Apache Jserv"))
    )
    host.ports.append(
        Port(number=445, protocol="tcp", state="open", service=Service(name="microsoft-ds", product="Samba"))
    )
    target.hosts[host.ip] = host

    web_targets = RealExecutionBackend._discover_web_targets(target)
    # Port 80 (SSH), 8009 (AJP), and 445 (SMB) must NOT be discovered as web targets
    assert len(web_targets) == 0


# ---------------------------------------------------------------------------
# 6. HTTP service on port 22 probed when protocol evidence confirms HTTP
# ---------------------------------------------------------------------------
def test_http_on_port_22_discovered_for_web():
    target = Target()
    host = Host(ip="10.49.160.134", status="up")
    host.ports.append(
        Port(number=22, protocol="tcp", state="open", service=Service(name="http", product="Apache httpd", version="2.4.10"))
    )
    target.hosts[host.ip] = host

    web_targets = RealExecutionBackend._discover_web_targets(target)
    assert len(web_targets) == 1
    assert web_targets[0].port == 22
    assert web_targets[0].url == "http://10.49.160.134:22"


# ---------------------------------------------------------------------------
# 7. SSH on port 80 must never be routed to HTTP
# ---------------------------------------------------------------------------
def test_ssh_on_port_80_never_routed_to_http():
    target = Target()
    host = Host(ip="10.49.160.134", status="up")
    host.ports.append(
        Port(number=80, protocol="tcp", state="open", service=Service(name="ssh", product="OpenSSH", version="6.7p1"))
    )
    target.hosts[host.ip] = host

    web_targets = RealExecutionBackend._discover_web_targets(target)
    assert not any(t.port == 80 for t in web_targets)


# ---------------------------------------------------------------------------
# 8 & 9. No-vulnerability report contains section and explicit no-matches text
# ---------------------------------------------------------------------------
def test_no_vulnerability_report_output():
    target = Target()
    host = Host(ip="10.10.10.50", status="up")
    host.ports.append(Port(number=22, protocol="tcp", state="open", service=Service(name="ssh", product="OpenSSH", version="9.9p1")))
    target.hosts[host.ip] = host

    reporter = TerminalReporter()
    string_io = StringIO()
    reporter.console = Console(file=string_io, highlight=False, force_terminal=False)
    reporter.report(target)
    output = string_io.getvalue()

    assert "VULNERABILITY ASSESSMENT" in output
    assert "Status: No matching vulnerabilities found" in output
    assert "No confirmed or potential vulnerabilities were identified" in output
    assert "from the available evidence" in output
    assert "Assessment coverage:" in output


# ---------------------------------------------------------------------------
# 11. Version applicability
# ---------------------------------------------------------------------------
def test_vulnerability_version_applicability():
    engine = VulnerabilityEngine()
    # Tomcat 9.0.35 is patched against Ghostcat (fixed in 9.0.31)
    host_fixed = Host(ip="10.0.0.1", status="up")
    host_fixed.ports.append(Port(number=8080, protocol="tcp", state="open", service=Service(name="http", product="Apache Tomcat", version="9.0.35")))
    host_fixed.ports.append(Port(number=8009, protocol="tcp", state="open", service=Service(name="ajp13", product="Apache Jserv")))
    target_fixed = Target(hosts={host_fixed.ip: host_fixed})

    engine.assess_target(target_fixed)
    ghostcat_fixed = [v for v in host_fixed.vulnerabilities if v.cve_id == "CVE-2020-1938"]
    assert len(ghostcat_fixed) == 0


# ---------------------------------------------------------------------------
# 12. Potential vs confirmed vulnerability confidence
# ---------------------------------------------------------------------------
def test_potential_vs_confirmed_confidence():
    engine = VulnerabilityEngine()
    host = Host(ip="10.0.0.2", status="up")
    host.ports.append(Port(number=80, protocol="tcp", state="open", service=Service(name="http", product="Apache httpd", version="2.4.49")))
    target = Target(hosts={host.ip: host})

    engine.assess_target(target)
    cve_41773 = next((v for v in host.vulnerabilities if v.cve_id == "CVE-2021-41773"), None)
    assert cve_41773 is not None
    # Detected by version banner -> POTENTIALLY_VULNERABLE (evidence-based)
    assert cve_41773.confidence in (Confidence.HIGH, Confidence.MEDIUM)


# ---------------------------------------------------------------------------
# 13. Internal session paths are not classified as intelligence findings
# ---------------------------------------------------------------------------
def test_internal_session_paths_not_classified(tmp_path):
    sample = tmp_path / "headers.txt"
    sample.write_text(
        "X-Debug-Session: ~/.sentinelrecon/sessions/session_2026-08-28/\n"
        "X-Report-Path: /opt/sentinelrecon/report.json\n"
        "Server: Apache/2.4.10\n",
        encoding="utf-8",
    )
    target = Analyzer().analyze_file(str(sample))
    host = next(iter(target.hosts.values()))
    unclass_values = [u.value for u in host.unclassified]
    assert not any("sessions/" in v for v in unclass_values)
    assert not any("sentinelrecon" in v for v in unclass_values)


# ---------------------------------------------------------------------------
# 14. Ordinary HTML links are not falsely classified as token-like findings
# ---------------------------------------------------------------------------
def test_ordinary_html_links_not_token_like(tmp_path):
    sample = tmp_path / "index.html"
    sample.write_text(
        "<a href='org/tomcat/FrontPage'>Tomcat Wiki</a>\n"
        "<a href='org/tomcat/Specifications'>Specs</a>\n"
        "<a href='https://github.com/apache/tomcat/tree/master'>Source</a>\n"
        "<p>Apache Software Foundation</p>\n",
        encoding="utf-8",
    )
    target = Analyzer().analyze_file(str(sample))
    host = next(iter(target.hosts.values()))
    unclass_kinds = {u.kind for u in host.unclassified}
    # Ordinary paths must NOT be classified as ENCODED/TOKEN-LIKE
    assert "ENCODED/TOKEN-LIKE" not in unclass_kinds


# ---------------------------------------------------------------------------
# 15 & 16. Package entry points
# ---------------------------------------------------------------------------
def test_entrypoints_version_and_imports():
    assert sentinelrecon.__version__ == "1.1.1"
    assert reconforge.__version__ == "1.1.1"


# ---------------------------------------------------------------------------
# 18. Arbitrary target input (positional IP, URL, custom ports)
# ---------------------------------------------------------------------------
def test_target_parser_arbitrary_inputs():
    t1 = TargetParser.parse("10.49.128.206")
    assert t1.target_type == "ip"
    assert t1.ip == "10.49.128.206"

    t2 = TargetParser.parse("http://10.49.160.134:8080")
    assert t2.target_type == "url"
    assert t2.ip == "10.49.160.134"
    assert t2.port == 8080

    t3 = TargetParser.parse("https://target.local:8443/app")
    assert t3.target_type == "url"
    assert t3.hostname == "target.local"
    assert t3.port == 8443
    assert t3.scheme == "https"


# ---------------------------------------------------------------------------
# 19. JSON vulnerability serialization
# ---------------------------------------------------------------------------
def test_json_vulnerability_serialization(tmp_path):
    target = Target()
    host = Host(ip="10.0.0.5", status="up")
    host.vulnerabilities.append(
        Vulnerability(
            cve_id="CVE-2020-1938",
            title="Ghostcat",
            description="AJP file read",
            severity="CRITICAL",
            cvss=9.8,
            cpe="cpe:2.3:a:apache:tomcat:9.0.30:*:*:*:*:*:*:*",
            cwe="CWE-20",
            kev_status=True,
            affected_product="Apache Tomcat",
            detected_version="9.0.30",
            confidence=Confidence.HIGH,
        )
    )
    target.hosts[host.ip] = host

    out_file = str(tmp_path / "report.json")
    JSONReporter().report(target, out_file)
    assert os.path.exists(out_file)

    with open(out_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "hosts" in data
    assert "10.0.0.5" in data["hosts"]
    vulns = data["hosts"]["10.0.0.5"]["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["cve_id"] == "CVE-2020-1938"
    assert vulns[0]["cvss"] == 9.8


# ---------------------------------------------------------------------------
# 20. HTML vulnerability serialization
# ---------------------------------------------------------------------------
def test_html_vulnerability_serialization(tmp_path):
    target = Target()
    host = Host(ip="10.0.0.5", status="up")
    host.vulnerabilities.append(
        Vulnerability(
            cve_id="CVE-2020-1938",
            title="Ghostcat",
            description="AJP file read",
            severity="CRITICAL",
            cvss=9.8,
            affected_product="Apache Tomcat",
            detected_version="9.0.30",
            confidence=Confidence.HIGH,
        )
    )
    target.hosts[host.ip] = host

    out_file = str(tmp_path / "report.html")
    HTMLReporter().report(target, out_file)
    assert os.path.exists(out_file)

    with open(out_file, "r", encoding="utf-8") as f:
        html = f.read()

    assert "CVE-2020-1938" in html
    assert "CRITICAL" in html
    assert "Apache Tomcat" in html


# ---------------------------------------------------------------------------
# 21. Automatic technology classification & composite profile composition
# ---------------------------------------------------------------------------
def test_technology_classification_and_composite_profile_composition():
    from sentinelrecon.core.discovery import (
        DiscoveryProfileComposer,
        TechnologyClassifier,
    )

    # Simulate detected Apache + PHP + WordPress
    host = Host(ip="10.10.10.60", status="up")
    host.ports.append(
        Port(
            number=80,
            protocol="tcp",
            state="open",
            service=Service(name="http", product="Apache httpd", version="2.4.41"),
        )
    )
    from sentinelrecon.core.models import Technology, WebEndpoint

    ep = WebEndpoint(
        url="http://10.10.10.60/",
        path="/",
        status_code=200,
        technologies=[
            Technology(name="WordPress", version="5.8"),
            Technology(name="PHP", version="7.4.3"),
        ],
    )
    host.web_endpoints.append(ep)
    target = Target(hosts={host.ip: host})

    detected_techs = TechnologyClassifier.classify_target(target, host=host)
    assert "WORDPRESS" in detected_techs
    assert "PHP" in detected_techs
    assert "APACHE" in detected_techs

    composer = DiscoveryProfileComposer()
    candidates, active_techs, exts = composer.compose_profile(
        depth="COMMON", technologies=detected_techs
    )

    # 1. Common baseline MUST be present
    assert "admin" in candidates or "admin/" in candidates
    assert "robots.txt" in candidates
    assert "login" in candidates

    # 2. Technology profiles MUST be added
    assert "wp-login.php" in candidates
    assert "wp-admin/" in candidates or "wp-admin" in candidates
    assert "server-status" in candidates
    assert "phpinfo.php" in candidates

    # 3. Extensions fused
    assert ".php" in exts


# ---------------------------------------------------------------------------
# 22. High-signal paths (/secret/, /backup/, /admin/, robots.txt) preserved
# ---------------------------------------------------------------------------
def test_high_signal_paths_preserved():
    from sentinelrecon.core.discovery import DiscoveryProfileComposer

    composer = DiscoveryProfileComposer()
    candidates, _, _ = composer.compose_profile(depth="COMMON")

    high_signal = ["secret", "secret/", "backup", "backups", "admin", "admin/", "robots.txt", "sitemap.xml", ".env", ".git/"]
    for path in high_signal:
        norm = composer.normalize_candidate(path)
        assert norm in candidates, f"High-signal path {path} (normalized: {norm}) missing from candidates"


# ---------------------------------------------------------------------------
# 23. Trailing-slash preservation (secret vs secret/, manager vs manager/)
# ---------------------------------------------------------------------------
def test_trailing_slash_preservation():
    from sentinelrecon.core.discovery import DiscoveryProfileComposer

    composer = DiscoveryProfileComposer()
    candidates, _, _ = composer.compose_profile(
        depth="COMMON", technologies={"TOMCAT", "WORDPRESS"}
    )

    # Verify directory indicators with trailing slash are preserved
    assert any(c.endswith("/") for c in candidates)
    # Check specific directory entries
    assert "wp-admin/" in candidates
    assert "manager/" in candidates or "manager/html" in candidates


# ---------------------------------------------------------------------------
# 24. Deduplication in composite wordlists
# ---------------------------------------------------------------------------
def test_deduplication_in_composite_wordlists(tmp_path):
    from sentinelrecon.core.discovery import DiscoveryProfileComposer

    composer = DiscoveryProfileComposer()
    file_path, active_techs, exts = composer.write_composite_wordlist(
        output_dir=str(tmp_path),
        depth="DEEP",
        technologies={"WORDPRESS", "APACHE", "PHP", "TOMCAT"},
    )
    assert os.path.exists(file_path)

    with open(file_path, "r", encoding="utf-8") as f:
        words = [line.strip() for line in f if line.strip()]

    assert len(words) == len(set(words)), "Composite wordlist contains duplicate entries!"


# ---------------------------------------------------------------------------
# 25. User home and internal runtime session path filtering
# ---------------------------------------------------------------------------
def test_home_and_internal_runtime_filtering(tmp_path):
    sample = tmp_path / "runtime_scan.txt"
    sample.write_text(
        "Nmap done at Fri Aug 28 17:00:00 2026 -- 1 IP address (1 host up) scanned in 2.15 seconds\n"
        "Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-08-28 17:00 EDT\n"
        "Output directory: /home/kali/.sentinelrecon/sessions/session_2026-08-28_17-00-00\n"
        "Command: nmap -sV -sC -p 80,443 -oA /home/kali/.sentinelrecon/sessions/session_2026-08-28_17-00-00/nmap 10.10.10.10\n"
        "Running Gobuster on http://10.10.10.10 with wordlist /opt/sentinelrecon/wordlists/common.txt\n"
        "flag{valid_secret_ctf_token_12345}\n",
        encoding="utf-8",
    )
    target = Analyzer().analyze_file(str(sample))
    host = next(iter(target.hosts.values()))
    unclass_values = [u.value for u in host.unclassified]

    # Must NOT classify internal execution paths
    assert not any("/home/kali" in v for v in unclass_values)
    assert not any("sessions/" in v for v in unclass_values)
    assert not any("nmap" in v.lower() and "http" in v.lower() for v in unclass_values)
    assert not any("/opt/sentinelrecon" in v for v in unclass_values)


# ---------------------------------------------------------------------------
# 26. AJP and SSH are never routed to web targets for directory enumeration
# ---------------------------------------------------------------------------
def test_ajp_and_ssh_not_in_web_targets():
    host = Host(ip="10.10.10.50", status="up")
    host.ports.append(
        Port(
            number=22,
            protocol="tcp",
            state="open",
            service=Service(name="ssh", product="OpenSSH", version="7.2p2"),
        )
    )
    host.ports.append(
        Port(
            number=8009,
            protocol="tcp",
            state="open",
            service=Service(name="ajp13", product="Apache Jserv", version="1.3"),
        )
    )
    host.ports.append(
        Port(
            number=8080,
            protocol="tcp",
            state="open",
            service=Service(name="http", product="Apache Tomcat", version="9.0.30"),
        )
    )
    target = Target(hosts={host.ip: host})

    web_targets = RealExecutionBackend._discover_web_targets(target)
    urls = [wt.url for wt in web_targets]

    assert "http://10.10.10.50:8080" in urls
    assert not any(":22" in u for u in urls), "SSH port 22 was incorrectly routed to web targets"
    assert not any(":8009" in u for u in urls), "AJP port 8009 was incorrectly routed to web targets"


# ---------------------------------------------------------------------------
# 27. Clean terminal output and no EVIDENCE & REPORTS in report
# ---------------------------------------------------------------------------
def test_clean_terminal_output_and_no_evidence_reports():
    target = Target()
    host = Host(ip="10.10.10.1", status="up")
    host.ports.append(
        Port(
            number=80,
            protocol="tcp",
            state="open",
            service=Service(name="http", product="nginx", version="1.18.0"),
        )
    )
    target.hosts[host.ip] = host

    reporter = TerminalReporter()
    output_buffer = StringIO()
    reporter.console = Console(file=output_buffer, highlight=False)
    reporter.report(target)
    output = output_buffer.getvalue()

    # Verify standard sections exist
    assert "SENTINELRECON ANALYSIS REPORT" in output
    assert "TARGET" in output
    assert "SERVICES" in output
    assert "VULNERABILITY ASSESSMENT" in output

    # Verify no internal leakage or legacy headers
    assert "EVIDENCE & REPORTS" not in output
    assert "ForgeProbe" not in output
    assert "/opt/sentinelrecon" not in output
    assert "/home/kali" not in output


# ---------------------------------------------------------------------------
# 28. Autonomous discovery profile composition for Tomcat
# ---------------------------------------------------------------------------
def test_autonomous_discovery_composition_for_tomcat():
    from sentinelrecon.core.discovery import (
        DiscoveryProfileComposer,
        TechnologyClassifier,
    )

    host = Host(ip="10.10.10.80", status="up")
    host.ports.append(
        Port(
            number=8080,
            protocol="tcp",
            state="open",
            service=Service(name="http", product="Apache Tomcat", version="9.0.30"),
        )
    )
    target = Target(hosts={host.ip: host})

    techs = TechnologyClassifier.classify_target(target)
    assert "TOMCAT" in techs

    composer = DiscoveryProfileComposer()
    candidates, active_techs, exts = composer.compose_profile(
        depth="AUTONOMOUS", technologies=techs
    )

    assert "TOMCAT" in active_techs
    assert "manager/html" in candidates
    assert "docs/" in candidates
    assert "admin" in candidates  # Common baseline preserved!


# ---------------------------------------------------------------------------
# 29. No Forge names in plan execution or module outputs
# ---------------------------------------------------------------------------
def test_no_forge_names_in_plan():
    target = ReconTarget(input="10.49.128.206", target_type="ip", ip="10.49.128.206", mode="Standard Recon")
    planner = ReconPlanner()
    plan = planner.plan(target)

    # Must contain capability names
    assert "Network Discovery" in plan.modules
    assert "Service Analysis" in plan.modules
    assert "Vulnerability Assessment" in plan.modules

    # Must NOT contain internal Forge names
    forge_names = ["ForgeDNS", "ForgeScan", "ForgeProbe", "ForgeTech", "ForgeDiscover", "SentinelCore", "ForgeTLS", "ForgeIntel", "ForgeReport"]
    for fn in forge_names:
        assert fn not in plan.modules, f"Found internal name {fn} in plan.modules"


# ---------------------------------------------------------------------------
# 30. Vulnerability assessment compact rendering for normal terminal width
# ---------------------------------------------------------------------------
def test_vulnerability_compact_rendering():
    target = Target()
    host = Host(ip="10.49.128.206", status="up")
    host.vulnerabilities.append(
        Vulnerability(
            cve_id="CVE-2020-1938",
            title="Apache Tomcat AJP Request Injection (Ghostcat)",
            description="AJP connector file read / inclusion",
            severity="CRITICAL",
            cvss=9.8,
            affected_product="Apache Tomcat",
            detected_version="9.0.30",
            affected_service="http",
            port=8080,
            confidence=Confidence.HIGH,
            reasoning="Tomcat AJP connector exposed on port 8009.",
            kev_status=True,
        )
    )
    target.hosts[host.ip] = host

    reporter = TerminalReporter()
    output_buffer = StringIO()
    reporter.console = Console(file=output_buffer, highlight=False)
    reporter.report(target)
    output = output_buffer.getvalue()

    assert "CRITICAL" in output
    assert "CVE-2020-1938" in output
    assert "Apache Tomcat" in output
    assert "Confidence: HIGH" in output
    assert "Ghostcat" in output
    assert "Tomcat AJP connector exposed on port 8009." in output


# ---------------------------------------------------------------------------
# 31. Synthetic test case: 22/tcp HTTP and 80/tcp SSH
# ---------------------------------------------------------------------------
def test_synthetic_22_http_and_80_ssh():
    from sentinelrecon.services.classifier import ServiceClassifier
    from sentinelrecon.vulnerability.engine import VulnerabilityEngine

    sc = ServiceClassifier()
    engine = VulnerabilityEngine()

    host = Host(ip="10.10.10.100", status="up")
    p_web = Port(22, "tcp", "open", Service(name="http", product="Apache httpd", version="2.4.10"))
    p_ssh = Port(80, "tcp", "open", Service(name="ssh", product="OpenSSH", version="6.7p1 Debian 5"))
    host.ports = [p_web, p_ssh]
    target = Target(hosts={host.ip: host})

    # 1. Classification
    c_web = sc.classify(p_web, host)
    c_ssh = sc.classify(p_ssh, host)

    assert c_web.is_web is True, "22/tcp HTTP should be classified as WEB"
    assert c_ssh.is_ssh is True, "80/tcp SSH should be classified as SSH"
    assert c_ssh.is_web is False, "80/tcp SSH must not be classified as WEB"

    # 2. HTTP Routing
    web_targets = RealExecutionBackend._discover_web_targets(target)
    urls = [wt.url for wt in web_targets]
    assert "http://10.10.10.100:22" in urls
    assert not any(":80" in u for u in urls), "80/tcp SSH must not enter web targets"

    # 3. Vulnerability Correlation
    engine.assess_target(target)
    ssh_vulns = [v for v in host.vulnerabilities if "OpenSSH" in (v.affected_product or "") or "SSH" in (v.affected_product or "") or "CVE-2018-15473" in (v.cve_id or "")]
    if ssh_vulns:
        assert ssh_vulns[0].port == 80, "OpenSSH CVE must be attached to port 80"

    # 4. Rendering format
    reporter = TerminalReporter()
    output_buffer = StringIO()
    reporter.console = Console(file=output_buffer, highlight=False)
    reporter.report(target)
    output = output_buffer.getvalue()

    # Must NOT duplicate service identifier (e.g. 80/tcp ssh / 80/tcp ssh)
    assert "80/tcp ssh / 80/tcp ssh" not in output
    assert "80/tcp SSH / 80/tcp SSH" not in output
    # Must NOT expose Python tuples (e.g. [('2.3', '7.7')])
    assert "[('" not in output


# ---------------------------------------------------------------------------
# 32. Synthetic test case: 8080/tcp Tomcat and 8009/tcp AJP (Ghostcat)
# ---------------------------------------------------------------------------
def test_synthetic_tomcat_8080_and_ajp_8009():
    from sentinelrecon.services.classifier import ServiceClassifier
    from sentinelrecon.vulnerability.engine import VulnerabilityEngine

    sc = ServiceClassifier()
    engine = VulnerabilityEngine()

    host = Host(ip="10.10.10.200", status="up")
    p_tomcat = Port(8080, "tcp", "open", Service(name="http", product="Apache Tomcat", version="9.0.30"))
    p_ajp = Port(8009, "tcp", "open", Service(name="ajp13", product="Apache Jserv", version="1.3"))
    host.ports = [p_tomcat, p_ajp]
    target = Target(hosts={host.ip: host})

    # 1. Routing
    web_targets = RealExecutionBackend._discover_web_targets(target)
    urls = [wt.url for wt in web_targets]
    assert "http://10.10.10.200:8080" in urls
    assert not any(":8009" in u for u in urls), "8009/tcp AJP must not enter web targets"

    # 2. Vulnerability Correlation
    engine.assess_target(target)
    ghostcat = next((v for v in host.vulnerabilities if v.cve_id == "CVE-2020-1938"), None)
    assert ghostcat is not None
    assert ghostcat.severity == "CRITICAL"
    assert ghostcat.port == 8080
    assert "8009" in ghostcat.reasoning
