import pytest
from unittest.mock import patch
from reconforge.cli import interactive_menu

@patch("builtins.input", side_effect=["1", "1", "10.48.159.132"])
def test_interactive_menu_ip(mock_input):
    target = interactive_menu()
    assert target.target_type == "ip"
    assert target.ip == "10.48.159.132"
    assert target.mode == "Standard Recon"

@patch("builtins.input", side_effect=["2", "2", "http://10.48.159.132", "1"])
def test_interactive_menu_url_default_port(mock_input):
    target = interactive_menu()
    assert target.target_type == "url"
    assert target.ip == "10.48.159.132"
    assert target.port == 80
    assert target.mode == "WAF-Aware Low-Impact Recon"

@patch("builtins.input", side_effect=["1", "2", "https://example.com", "2", "8443"])
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
