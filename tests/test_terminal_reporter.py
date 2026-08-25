import os
import json
import tempfile
from io import StringIO
import pytest
from rich.console import Console

from reconforge.core.models import Target, Host, WebEndpoint, Service, Port, Evidence
from reconforge.reporters.terminal import TerminalReporter
from reconforge.reporters.json_ext import JSONReporter
from reconforge.reporters.html import HTMLReporter

def test_terminal_reporter_url_formatting_and_sections():
    target = Target()
    host = Host(ip="10.0.2.14", status="up")

    # Add open HTTP port 80
    host.ports.append(Port(number=80, protocol="tcp", state="open", service=Service(name="http", product="Apache", version="2.4.41")))

    # Endpoint 1: Root /
    ep1 = WebEndpoint(url="http://10.0.2.14/", path="/", status_codes=[200], sources={"200": ["gobuster"]})
    # Endpoint 2: /secret/ with size
    ep2 = WebEndpoint(url="http://10.0.2.14/secret/", path="/secret/", status_codes=[200], content_length=1234, sources={"200": ["dirb"]})
    # Endpoint 3: /secret without trailing slash (301 redirect)
    ep3 = WebEndpoint(url="http://10.0.2.14/secret", path="/secret", status_codes=[301], redirect_location="http://10.0.2.14/secret/", sources={"301": ["http_collector"]})
    # Endpoint 4: Custom port 8081 endpoint
    ep4 = WebEndpoint(url="http://10.0.2.14:8081/admin/", path="/admin/", status_codes=[403], content_length=274, sources={"403": ["gobuster"]})
    # Endpoint 5: HTTPS custom port 8443 endpoint
    ep5 = WebEndpoint(url="https://10.0.2.14:8443/login/", path="/login/", status_codes=[200], content_length=500, sources={"200": ["tls_collector"]})

    host.web_endpoints.extend([ep1, ep2, ep3, ep4, ep5])
    target.hosts["10.0.2.14"] = host
    target.evidence.append(Evidence(source_file="nmap.xml", source_type="NmapXMLParser", content="<xml/>"))

    # Capture terminal output
    io = StringIO()
    console = Console(file=io, force_terminal=False, width=120)
    reporter = TerminalReporter()
    reporter.console = console

    reporter.report(target)
    output = io.getvalue()

    # 1. Full URL displayed
    assert "http://10.0.2.14/secret/" in output
    assert "http://10.0.2.14:8081/admin/" in output
    assert "https://10.0.2.14:8443/login/" in output

    # 2. Sources column absent
    assert "Sources" not in output
    assert "dirb" not in output  # internal parser/source tool names omitted from directory table

    # 3. SESSION EVIDENCE absent
    assert "SESSION EVIDENCE" not in output

    # 4. REPORTS & EVIDENCE SUMMARY absent
    assert "REPORTS & EVIDENCE SUMMARY" not in output

    # 4b. EXECUTION SUMMARY absent from normal terminal output
    assert "EXECUTION SUMMARY" not in output


    # 5. HTTP and HTTPS remain distinct
    assert "http://10.0.2.14/" in output
    assert "https://10.0.2.14:8443/login/" in output

    # 6. Different ports remain distinct
    assert "http://10.0.2.14:8081/admin/" in output

    # 7. /secret and /secret/ remain distinct
    assert "http://10.0.2.14/secret/" in output
    assert "http://10.0.2.14/secret" in output

    # 8. Status codes remain visible
    assert "200" in output
    assert "301" in output
    assert "403" in output

    # 9. Content size remains visible
    assert "Size: 1234" in output
    assert "Size: 274" in output

    # 10. Redirect location remains visible
    assert "--> http://10.0.2.14/secret/" in output

    # 11. Internal source/provenance remains intact in model
    assert ep1.sources == {"200": ["gobuster"]}
    assert ep2.sources == {"200": ["dirb"]}
    assert ep3.sources == {"301": ["http_collector"]}

def test_json_and_html_reporters_preserve_complete_data(tmp_path):
    target = Target()
    host = Host(ip="10.0.2.14", status="up")
    ep1 = WebEndpoint(url="http://10.0.2.14/secret/", path="/secret/", status_codes=[200], sources={"200": ["gobuster"]})
    host.web_endpoints.append(ep1)
    target.hosts["10.0.2.14"] = host
    target.evidence.append(Evidence(source_file="nmap.xml", source_type="NmapXMLParser", content="<xml/>"))

    # Test 12: JSON report preserves complete data
    json_file = tmp_path / "report.json"
    json_rep = JSONReporter()
    json_rep.report(target, str(json_file))

    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "10.0.2.14" in data["hosts"]
    endpoints = data["hosts"]["10.0.2.14"]["web_endpoints"]
    assert len(endpoints) == 1
    assert endpoints[0]["url"] == "http://10.0.2.14/secret/"
    assert endpoints[0]["sources"] == {"200": ["gobuster"]}
    assert len(data["evidence"]) == 1

    # Test 13: HTML report preserves complete data
    html_file = tmp_path / "report.html"
    html_rep = HTMLReporter()
    html_rep.report(target, str(html_file))

    with open(html_file, "r", encoding="utf-8") as f:
        html_content = f.read()

    assert "10.0.2.14" in html_content
    assert "/secret/" in html_content
