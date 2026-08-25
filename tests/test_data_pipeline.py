import pytest
from reconforge.core.models import Target, Host, WebEndpoint, Service, Port, Technology, Confidence
from reconforge.core.analyzer import Analyzer
from reconforge.parsers.web import GobusterParser, DirbParser
from reconforge.parsers.http import HTTPParser
from reconforge.reporters.terminal import TerminalReporter
from reconforge.reporters.json_ext import JSONReporter
import json
import tempfile
import os

def test_preserve_trailing_slash_semantics():
    analyzer = Analyzer()
    target = Target()

    host1 = Host(ip="10.0.2.14", status="up")
    ep1 = WebEndpoint(url="http://10.0.2.14/secret/", path="/secret/", status_codes=[200], sources={"200": ["module_a"]})
    host1.web_endpoints.append(ep1)

    host2 = Host(ip="10.0.2.14", status="up")
    ep2 = WebEndpoint(url="http://10.0.2.14/secret", path="/secret", status_codes=[301], redirect_location="http://10.0.2.14/secret/", sources={"301": ["module_b"]})
    host2.web_endpoints.append(ep2)

    analyzer._merge_host(target, host1)
    analyzer._merge_host(target, host2)

    merged_host = target.hosts["10.0.2.14"]
    paths = [ep.path for ep in merged_host.web_endpoints]
    assert "/secret/" in paths
    assert "/secret" in paths
    assert len(merged_host.web_endpoints) == 2

def test_endpoint_multi_source_and_status_aggregation():
    analyzer = Analyzer()
    target = Target()

    host1 = Host(ip="10.0.2.14", status="up")
    ep1 = WebEndpoint(url="http://10.0.2.14/admin/", path="/admin/", status_codes=[200], sources={"200": ["gobuster"]})
    host1.web_endpoints.append(ep1)

    host2 = Host(ip="10.0.2.14", status="up")
    ep2 = WebEndpoint(url="http://10.0.2.14/admin/", path="/admin/", status_codes=[403], sources={"403": ["http_collector"]})
    host2.web_endpoints.append(ep2)

    analyzer._merge_host(target, host1)
    analyzer._merge_host(target, host2)

    merged_host = target.hosts["10.0.2.14"]
    assert len(merged_host.web_endpoints) == 1

    ep = merged_host.web_endpoints[0]
    assert set(ep.status_codes) == {200, 403}
    assert "gobuster" in ep.sources.get("200", [])
    assert "http_collector" in ep.sources.get("403", [])

def test_different_ports_and_schemes_isolation():
    analyzer = Analyzer()
    target = Target()

    host1 = Host(ip="10.0.2.14", status="up")
    ep1 = WebEndpoint(url="http://10.0.2.14:80/api", path="/api", status_codes=[200])
    ep2 = WebEndpoint(url="http://10.0.2.14:8080/api", path="/api", status_codes=[200])
    ep3 = WebEndpoint(url="https://10.0.2.14:443/api", path="/api", status_codes=[200])
    host1.web_endpoints.extend([ep1, ep2, ep3])

    analyzer._merge_host(target, host1)

    merged_host = target.hosts["10.0.2.14"]
    assert len(merged_host.web_endpoints) == 3

def test_dirb_parser_directory_line():
    content = "==> DIRECTORY: http://10.0.2.14/secret/\n+ http://10.0.2.14/secret/index.html (CODE:200|SIZE:500)\n"
    with tempfile.NamedTemporaryFile(suffix=".txt", mode="w", delete=False) as f:
        f.write(content)
        temp_name = f.name

    try:
        hosts, findings, errors = DirbParser.parse(temp_name)
        assert len(hosts) == 1
        paths = [ep.path for ep in hosts[0].web_endpoints]
        assert "/secret/" in paths
        assert "/secret/index.html" in paths
    finally:
        if os.path.exists(temp_name):
            os.remove(temp_name)

def test_gobuster_parser_special_chars_and_found_prefix():
    content = "Found: /secret/ (Status: 200) [Size: 1234]\nFound: /api-v1.0/user?id=1 (Status: 200) [Size: 50]\n"
    with tempfile.NamedTemporaryFile(suffix=".txt", mode="w", delete=False) as f:
        f.write(content)
        temp_name = f.name

    try:
        hosts, findings, errors = GobusterParser.parse(temp_name)
        assert len(hosts) == 1
        paths = [ep.path for ep in hosts[0].web_endpoints]
        assert "/secret/" in paths
        assert "/api-v1.0/user?id=1" in paths
    finally:
        if os.path.exists(temp_name):
            os.remove(temp_name)

def test_http_parser_technologies_and_location():
    content = "HTTP/1.1 301 Moved Permanently\nServer: Apache/2.4.41 (Ubuntu)\nX-Powered-By: PHP/7.4.3\nLocation: /secret/\n\n"
    with tempfile.NamedTemporaryFile(suffix=".txt", mode="w", delete=False) as f:
        f.write(content)
        temp_name = f.name

    try:
        hosts, findings, errors = HTTPParser.parse(temp_name)
        assert len(hosts) == 1
        ep = hosts[0].web_endpoints[0]
        assert ep.redirect_location == "/secret/"
        tech_names = [t.name for t in ep.technologies]
        assert "Apache" in tech_names
        assert "PHP" in tech_names
    finally:
        if os.path.exists(temp_name):
            os.remove(temp_name)

def test_serialization_and_reporting():
    target = Target()
    host = Host(ip="10.0.2.14", status="up")
    ep1 = WebEndpoint(url="http://10.0.2.14/secret/", path="/secret/", status_codes=[200], sources={"200": ["gobuster"]})
    ep2 = WebEndpoint(url="http://10.0.2.14/admin/panel/", path="/admin/panel/", status_codes=[403], sources={"403": ["dirb"]})
    host.web_endpoints.extend([ep1, ep2])
    target.hosts["10.0.2.14"] = host

    # Test JSON serialization
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        json_path = f.name

    try:
        reporter = JSONReporter()
        reporter.report(target, json_path)

        with open(json_path, "r") as f:
            data = json.load(f)

        assert "10.0.2.14" in data["hosts"]
        endpoints = data["hosts"]["10.0.2.14"]["web_endpoints"]
        paths = [e["path"] for e in endpoints]
        assert "/secret/" in paths
        assert "/admin/panel/" in paths
    finally:
        if os.path.exists(json_path):
            os.remove(json_path)

    # Test TerminalReporter rendering does not error
    term_reporter = TerminalReporter()
    term_reporter.report(target)
