"""Deterministic integration test suite for TomGhost CTF vulnerability correlation and AJP intelligence."""

import json
import pytest
from io import StringIO
from rich.console import Console

from reconforge.core.models import Confidence, FindingType, Host, Port, Service, Target
from reconforge.core.services import ServiceCapability, ServiceClassifier, ServiceCapabilityRouter
from reconforge.core.vulnerability_intel import VulnerabilityIntel, NVDClient
from reconforge.reporters.terminal import TerminalReporter
from reconforge.reporters.json_ext import JSONReporter
from reconforge.reporters.html import HTMLReporter


class DummyNVDClient(NVDClient):
    """Offline stub for deterministic, fast unit tests."""
    def vulnerabilities_for_cpe(self, cpe: str):
        return []


@pytest.fixture
def offline_vintel():
    return VulnerabilityIntel(client=DummyNVDClient())


@pytest.fixture
def tomghost_target():
    """Build synthetic TomGhost reconnaissance result object (10.49.128.206)."""
    target = Target()
    host = Host(ip="10.49.128.206", status="up")

    # 1. 22/tcp OpenSSH
    host.ports.append(
        Port(
            number=22,
            protocol="tcp",
            state="open",
            service=Service(name="ssh", product="OpenSSH", version="7.2p2 Ubuntu 4ubuntu2.8"),
        )
    )

    # 2. 53/tcp tcpwrapped
    host.ports.append(
        Port(
            number=53,
            protocol="tcp",
            state="open",
            service=Service(name="tcpwrapped", product="", version=""),
        )
    )

    # 3. 8009/tcp ajp13 Apache Jserv
    host.ports.append(
        Port(
            number=8009,
            protocol="tcp",
            state="open",
            service=Service(name="ajp13", product="Apache Jserv", version="1.3"),
        )
    )

    # 4. 8080/tcp http Apache Tomcat 9.0.30
    host.ports.append(
        Port(
            number=8080,
            protocol="tcp",
            state="open",
            service=Service(name="http", product="Apache Tomcat", version="9.0.30"),
        )
    )

    target.hosts[host.ip] = host
    return target


def test_service_classification_ajp():
    """Verify AJP service is recognized and classified properly without mislabeling as HTTP."""
    classifier = ServiceClassifier()
    ajp_port = Port(
        number=8009,
        protocol="tcp",
        state="open",
        service=Service(name="ajp13", product="Apache Jserv", version="1.3"),
    )
    classification = classifier.classify(ajp_port)
    assert classification.is_ajp is True
    assert classification.is_web is False
    assert classification.capability == ServiceCapability.AJP
    assert "AJP13" in classification.description

    router = ServiceCapabilityRouter(classifier)
    route_desc = router.get_route_description(ajp_port)
    assert "AJP" in route_desc


def test_tomghost_both_services_survive_and_preserve_metadata(tomghost_target):
    """Verify both AJP (8009) and Tomcat (8080) survive and preserve exact attributes."""
    host = tomghost_target.hosts["10.49.128.206"]
    ports = {p.number: p for p in host.ports}

    assert 8009 in ports
    assert ports[8009].service.name == "ajp13"
    assert ports[8009].service.product == "Apache Jserv"

    assert 8080 in ports
    assert ports[8080].service.name == "http"
    assert ports[8080].service.product == "Apache Tomcat"
    assert ports[8080].service.version == "9.0.30"


def test_tomghost_vulnerability_correlation_matches_ghostcat(tomghost_target, offline_vintel):
    """Verify CVE-2020-1938 matches Apache Tomcat 9.0.30 with cross-service AJP evidence."""
    added = offline_vintel.enrich(tomghost_target)
    assert added > 0

    host = tomghost_target.hosts["10.49.128.206"]
    cves = {v.cve_id: v for v in host.vulnerabilities}

    # Verify CVE-2020-1938 (Ghostcat) matched with high confidence due to AJP presence
    assert "CVE-2020-1938" in cves
    ghostcat = cves["CVE-2020-1938"]
    assert ghostcat.severity == "CRITICAL"
    assert ghostcat.cvss == 9.8
    assert ghostcat.confidence == Confidence.HIGH
    assert ghostcat.detected_version == "9.0.30"

    # Verify multi-service cross correlation evidence
    evidence_contents = [e.content for e in ghostcat.evidence]
    assert any("8080" in c for c in evidence_contents)
    assert any("8009" in c or "AJP" in c for c in evidence_contents)


def test_tomghost_finding_generation(tomghost_target, offline_vintel):
    """Verify proper FindingType.VULNERABILITY is created in host.findings."""
    offline_vintel.enrich(tomghost_target)

    host = tomghost_target.hosts["10.49.128.206"]
    vuln_findings = [f for f in host.findings if f.finding_type == FindingType.VULNERABILITY]
    assert len(vuln_findings) > 0
    assert any("Ghostcat" in f.title or "CVE-2020-1938" in f.title for f in vuln_findings)


def test_fixed_tomcat_does_not_match_cve_2020_1938(offline_vintel):
    """Verify no false positive when Tomcat is on fixed version (e.g. 9.0.31)."""
    target = Target()
    host = Host(ip="10.49.128.207", status="up")
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
            service=Service(name="http", product="Apache Tomcat", version="9.0.31"),
        )
    )
    target.hosts[host.ip] = host

    offline_vintel.enrich(target)

    cves = {v.cve_id: v for v in host.vulnerabilities}
    assert "CVE-2020-1938" not in cves


def test_terminal_report_renders_vulnerability_assessment(tomghost_target, offline_vintel):
    """Verify terminal reporter renders VULNERABILITY ASSESSMENT with table and stats."""
    offline_vintel.enrich(tomghost_target)

    reporter = TerminalReporter()
    string_io = StringIO()
    reporter.console = Console(file=string_io, highlight=False, force_terminal=False)
    reporter.report(tomghost_target)
    output = string_io.getvalue()

    assert "VULNERABILITY ASSESSMENT" in output
    assert "CVE-2020-1938" in output
    assert "Services assessed:" in output
    assert "Products assessed:" in output
    assert "Vulnerability records evaluated:" in output
    assert "8009/tcp" in output
    assert "ajp13" in output


def test_terminal_report_renders_empty_vulnerability_assessment():
    """Verify terminal reporter renders VULNERABILITY ASSESSMENT even when zero matches exist."""
    target = Target()
    host = Host(ip="10.49.128.208", status="up")
    host.ports.append(
        Port(
            number=22,
            protocol="tcp",
            state="open",
            service=Service(name="ssh", product="CustomSSH", version="99.9"),
        )
    )
    target.hosts[host.ip] = host

    reporter = TerminalReporter()
    string_io = StringIO()
    reporter.console = Console(file=string_io, highlight=False, force_terminal=False)
    reporter.report(target)
    output = string_io.getvalue()

    assert "VULNERABILITY ASSESSMENT" in output
    assert "Status: No matching vulnerabilities found" in output
    assert "Services assessed:" in output


def test_json_and_html_report_preserves_vulnerability(tmp_path, tomghost_target, offline_vintel):
    """Verify JSON and HTML reports preserve the vulnerability assessment finding and evidence."""
    offline_vintel.enrich(tomghost_target)

    json_path = str(tmp_path / "report.json")
    html_path = str(tmp_path / "report.html")

    JSONReporter().report(tomghost_target, json_path)
    HTMLReporter().report(tomghost_target, html_path)

    with open(json_path, "r", encoding="utf-8") as f:
        json_data = json.load(f)
    host_json = json_data["hosts"]["10.49.128.206"]
    assert any(v["cve_id"] == "CVE-2020-1938" for v in host_json["vulnerabilities"])

    with open(html_path, "r", encoding="utf-8") as f:
        html_data = f.read()
    assert "Vulnerability Assessment" in html_data
    assert "CVE-2020-1938" in html_data
    assert "8009" in html_data
