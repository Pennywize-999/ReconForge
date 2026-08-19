import pytest
from reconforge.core.target_parser import parse_target, is_valid_ip

def test_is_valid_ip():
    assert is_valid_ip("10.48.159.132") == True
    assert is_valid_ip("127.0.0.1") == True
    assert is_valid_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == True
    assert is_valid_ip("example.com") == False
    assert is_valid_ip("http://10.48.159.132") == False
    assert is_valid_ip("999.999.999.999") == False

def test_parse_target_ip():
    target = parse_target("10.48.159.132")
    assert target.target_type == "ip"
    assert target.ip == "10.48.159.132"
    assert target.hostname is None
    assert target.scheme is None
    assert target.port is None

def test_parse_target_url_with_ip():
    target = parse_target("http://10.48.159.132:5000")
    assert target.target_type == "url"
    assert target.ip == "10.48.159.132"
    assert target.hostname is None
    assert target.scheme == "http"
    assert target.port == 5000
    assert target.url == "http://10.48.159.132:5000"

def test_parse_target_url_with_hostname():
    target = parse_target("https://example.com")
    assert target.target_type == "url"
    assert target.ip is None
    assert target.hostname == "example.com"
    assert target.scheme == "https"
    assert target.port == 443
    assert target.url == "https://example.com:443"

def test_parse_target_url_with_hostname_and_custom_port():
    target = parse_target("https://example.com:8443")
    assert target.target_type == "url"
    assert target.ip is None
    assert target.hostname == "example.com"
    assert target.scheme == "https"
    assert target.port == 8443
    assert target.url == "https://example.com:8443"

def test_parse_target_invalid():
    target = parse_target("just_a_string")
    assert target.target_type == "unknown"
    assert target.hostname == "just_a_string"
    assert target.ip is None
