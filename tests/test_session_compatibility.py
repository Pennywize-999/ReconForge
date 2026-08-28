"""Unit tests for backward-compatible session serialization and model deserialization."""

import json
from sentinelrecon.core.models import (
    Confidence,
    Evidence,
    Finding,
    FindingType,
    Host,
    ModelEncoder,
    Port,
    ScanSession,
    Service,
    Target,
    Vulnerability,
)


def test_session_serialization_roundtrip():
    target = Target()
    host = Host(ip="192.168.1.100", status="up")
    host.ports.append(
        Port(
            number=80,
            protocol="tcp",
            state="open",
            service=Service(name="http", product="nginx", version="1.18.0"),
        )
    )
    host.findings.append(
        Finding(
            title="HTTP Server Header Disclosed",
            finding_type=FindingType.INFORMATION,
            severity="INFO",
            confidence=Confidence.HIGH,
            description="nginx 1.18.0 detected",
            evidence=[Evidence(source_file="headers.txt", source_type="HTTP Response Analysis", content="Server: nginx/1.18.0")],
        )
    )
    target.hosts[host.ip] = host

    session = ScanSession(id="session_test_001", timestamp="2026-08-28_15-00-00", target=target)

    # Serialize
    raw_json = json.dumps(session, cls=ModelEncoder)
    loaded_dict = json.loads(raw_json)

    # Deserialize
    deserialized = ScanSession.from_dict(loaded_dict)
    assert deserialized.id == "session_test_001"
    assert "192.168.1.100" in deserialized.target.hosts
    loaded_host = deserialized.target.hosts["192.168.1.100"]
    assert loaded_host.ports[0].service.product == "nginx"
    assert loaded_host.findings[0].finding_type == FindingType.INFORMATION


def test_legacy_vulnerability_deserialization():
    """Verify deserialization handles legacy fields like affected_version smoothly."""
    legacy_data = {
        "cve_id": "CVE-2020-1938",
        "title": "Ghostcat",
        "description": "Legacy format vulnerability",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "affected_product": "Apache Tomcat",
        "affected_version": "9.0.30",
        "confidence": "HIGH",
        "source": "Legacy Engine",
    }
    vuln = Vulnerability.from_dict(legacy_data)
    assert vuln.cve_id == "CVE-2020-1938"
    assert vuln.detected_version == "9.0.30"
    assert vuln.confidence == Confidence.HIGH
