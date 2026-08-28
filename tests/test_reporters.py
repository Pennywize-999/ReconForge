"""Unit tests for SentinelRecon Terminal, JSON, and HTML Reporters."""

import json
from io import StringIO
from rich.console import Console

from sentinelrecon.core.models import Confidence, Host, Port, Service, Target, Vulnerability
from sentinelrecon.reporters.html import HTMLReporter
from sentinelrecon.reporters.json_ext import JSONReporter
from sentinelrecon.reporters.terminal import TerminalReporter


def test_terminal_reporter_empty_vulnerabilities():
    target = Target()
    host = Host(ip="10.10.10.1", status="up")
    host.ports.append(
        Port(number=80, protocol="tcp", state="open", service=Service(name="http", product="CustomApp"))
    )
    target.hosts[host.ip] = host

    string_io = StringIO()
    reporter = TerminalReporter()
    reporter.console = Console(file=string_io, highlight=False, force_terminal=False)
    reporter.report(target)
    output = string_io.getvalue()

    assert "VULNERABILITY ASSESSMENT" in output
    assert "Status: No matching vulnerabilities found" in output
    assert "No confirmed or potential vulnerabilities were identified" in output
    assert "Assessment coverage:" in output


def test_html_and_json_reporters_render(tmp_path):
    target = Target()
    host = Host(ip="10.10.10.2", status="up")
    host.vulnerabilities.append(
        Vulnerability(
            cve_id="CVE-2020-1938",
            title="Ghostcat",
            description="AJP connector injection",
            severity="CRITICAL",
            cvss=9.8,
            affected_product="Apache Tomcat",
            detected_version="9.0.30",
            confidence=Confidence.HIGH,
        )
    )
    target.hosts[host.ip] = host

    json_path = str(tmp_path / "report.json")
    html_path = str(tmp_path / "report.html")

    JSONReporter().report(target, json_path)
    HTMLReporter().report(target, html_path)

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["hosts"]["10.10.10.2"]["vulnerabilities"][0]["cve_id"] == "CVE-2020-1938"

    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()
    assert "SentinelRecon" in html
    assert "CVE-2020-1938" in html
