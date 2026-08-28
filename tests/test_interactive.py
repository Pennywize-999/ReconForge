import pytest
from unittest.mock import patch
from sentinelrecon.interactive import interactive_menu


@patch("builtins.input", side_effect=["10.48.159.132", "1"])
def test_interactive_menu_ip(mock_input):
    target = interactive_menu()
    assert target.target_type == "ip"
    assert target.ip == "10.48.159.132"
    assert target.mode == "Standard Recon"
    assert target.discovery_profile == "AUTONOMOUS"


@patch("builtins.input", side_effect=["http://10.48.159.132", "2", "1"])
def test_interactive_menu_url_default_port(mock_input):
    target = interactive_menu()
    assert target.target_type == "url"
    assert target.ip == "10.48.159.132"
    assert target.port == 80
    assert target.mode == "WAF-Aware Low-Impact Recon"


@patch("builtins.input", side_effect=["https://example.com", "1", "2", "8443"])
def test_interactive_menu_url_custom_port(mock_input):
    target = interactive_menu()
    assert target.target_type == "url"
    assert target.hostname == "example.com"
    assert target.port == 8443
    assert target.mode == "Standard Recon"


@patch("builtins.input", side_effect=KeyboardInterrupt)
def test_interactive_menu_keyboard_interrupt(mock_input):
    with pytest.raises(SystemExit) as excinfo:
        interactive_menu()
    assert excinfo.value.code == 0
