"""Unit tests for ServiceClassifier and ServiceCapabilityRouter."""

import pytest
from reconforge.core.models import Host, Port, Service, Target
from reconforge.core.services import ServiceCapability, ServiceClassifier, ServiceCapabilityRouter


def test_classify_ajp_service():
    classifier = ServiceClassifier()
    p = Port(number=8009, protocol="tcp", state="open", service=Service(name="ajp13", product="Apache Jserv"))
    c = classifier.classify(p)
    assert c.capability == ServiceCapability.AJP
    assert c.is_ajp is True


def test_classify_web_service():
    classifier = ServiceClassifier()
    p1 = Port(number=80, protocol="tcp", state="open", service=Service(name="http", product="Apache httpd", version="2.4.41"))
    c1 = classifier.classify(p1)
    assert c1.capability == ServiceCapability.WEB
    assert c1.is_web is True
    assert c1.is_tls is False

    p2 = Port(number=443, protocol="tcp", state="open", service=Service(name="https", product="nginx", version="1.18.0"))
    c2 = classifier.classify(p2)
    assert c2.capability == ServiceCapability.WEB
    assert c2.is_web is True
    assert c2.is_tls is True


def test_classify_ssh_service():
    classifier = ServiceClassifier()
    p = Port(number=22, protocol="tcp", state="open", service=Service(name="ssh", product="OpenSSH", version="8.2p1"))
    c = classifier.classify(p)
    assert c.capability == ServiceCapability.SSH


def test_classify_smb_and_dns():
    classifier = ServiceClassifier()
    p_smb = Port(number=445, protocol="tcp", state="open", service=Service(name="microsoft-ds", product="Samba"))
    assert classifier.classify(p_smb).capability == ServiceCapability.SMB

    p_dns = Port(number=53, protocol="tcp", state="open", service=Service(name="domain", product="BIND"))
    assert classifier.classify(p_dns).capability == ServiceCapability.DNS


def test_capability_router():
    router = ServiceCapabilityRouter()
    p_ajp = Port(number=8009, protocol="tcp", state="open", service=Service(name="ajp13", product="Apache Jserv"))
    assert "AJP" in router.get_route_description(p_ajp)

    p_web = Port(number=8080, protocol="tcp", state="open", service=Service(name="http", product="Apache Tomcat"))
    assert "HTTP Probing -> Technology Detection -> Content Discovery" in router.get_route_description(p_web)
    assert "Forge" not in router.get_route_description(p_web)
