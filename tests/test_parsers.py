import os
import pytest
from reconforge.parsers.nmap import NmapXMLParser
from reconforge.parsers.web import GobusterParser, DirbParser
from reconforge.parsers.whatweb import WhatWebParser
from reconforge.parsers.http import HTTPParser
from reconforge.parsers.tls import TLSParser
from reconforge.parsers.dns import DNSParser
from reconforge.parsers.smb import SMBParser
from reconforge.parsers.generic import GenericTextParser
from reconforge.core.analyzer import Analyzer
from reconforge.core.session import SessionManager
from reconforge.core.models import Target, Host, Confidence
from reconforge.web.waf.analyzer import WAFAnalyzer

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')

def get_fixture(filename):
    return os.path.join(FIXTURES_DIR, filename)

def test_nmap_parser():
    file_path = get_fixture('sample.xml')
    assert NmapXMLParser.can_parse(file_path)

    hosts, findings, errors = NmapXMLParser.parse(file_path)
    assert not errors
    assert len(hosts) == 1

    host = hosts[0]
    assert host.ip == "10.10.10.25"
    assert host.status == "up"
    assert len(host.ports) == 2

def test_whatweb_parser():
    file_path = get_fixture('whatweb.txt')
    assert WhatWebParser.can_parse(file_path)

    hosts, findings, errors = WhatWebParser.parse(file_path)
    assert not errors
    assert len(hosts) == 1

    host = hosts[0]
    assert host.hostnames[0] == "10.10.10.25"
    assert len(host.web_endpoints) == 1

    ep = host.web_endpoints[0]
    assert ep.status_codes[0] == 200
    assert len(ep.technologies) > 0

def test_tls_parser():
    file_path = get_fixture('10.10.10.25_tls.txt')
    assert TLSParser.can_parse(file_path)

    hosts, findings, errors = TLSParser.parse(file_path)
    assert not errors
    assert len(hosts) == 1

    host = hosts[0]
    assert host.ip == "10.10.10.25"
    assert "web01.local" in host.hostnames

    assert len(host.findings) == 2

def test_dns_parser():
    file_path = get_fixture('dns.txt')
    assert DNSParser.can_parse(file_path)

    hosts, findings, errors = DNSParser.parse(file_path)
    assert not errors
    assert len(hosts) == 2
    assert len(findings) == 1
    assert findings[0].title == "DNS Zone Transfer (AXFR) Successful"

def test_smb_parser():
    file_path = get_fixture('10.10.10.25_smb.txt')
    assert SMBParser.can_parse(file_path)

    hosts, findings, errors = SMBParser.parse(file_path)
    assert not errors
    assert len(hosts) == 1
    assert len(hosts[0].findings) == 2

def test_analyzer_correlation():
    analyzer = Analyzer()
    target = analyzer.analyze_directory(FIXTURES_DIR)

    # We should have consolidated most things under 10.10.10.25 and maybe 10.10.10.26 from DNS
    assert "10.10.10.25" in target.hosts
    host = target.hosts["10.10.10.25"]

    # Check if hostnames were merged (web01.local from TLS and DNS)
    assert "web01.local" in host.hostnames

    # Check if we merged Nmap and Gobuster web endpoints
    assert len(host.web_endpoints) >= 4

    # Check vulnerabilities
    cve_vulns = [v for v in host.vulnerabilities if v.cve_id]
    assert len(cve_vulns) >= 1

def test_session_manager():
    analyzer = Analyzer()
    target = analyzer.analyze_directory(FIXTURES_DIR)

    manager = SessionManager()
    session = manager.create_session(target)

    loaded_session = manager.load_session(session.id)
    assert loaded_session.id == session.id
    assert "10.10.10.25" in loaded_session.target.hosts

    # Verify complex object deserialization worked
    host = loaded_session.target.hosts["10.10.10.25"]
    assert hasattr(host, "web_endpoints")
    if host.vulnerabilities:
        assert isinstance(host.vulnerabilities[0].confidence, Confidence)

def test_waf_analyzer():
    analyzer = Analyzer()
    target = analyzer.analyze_directory(FIXTURES_DIR)

    assert "10.10.10.27" in target.hosts
    host = target.hosts["10.10.10.27"]

    assert host.waf_analysis is not None
    waf = host.waf_analysis

    assert waf.detected is True
    assert waf.provider == "Cloudflare"
    assert waf.provider_confidence == Confidence.HIGH
    assert waf.rate_limiting is True
    assert waf.status_counts.get("403", 0) >= 10
    assert waf.status_counts.get("429", 0) >= 2
    assert waf.low_impact_profile is not None
