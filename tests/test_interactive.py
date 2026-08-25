import pytest
from unittest.mock import patch
from reconforge.cli import interactive_menu

@patch("builtins.input", side_effect=["10.48.159.132", "1", "1"])
def test_interactive_menu_ip(mock_input):
    target = interactive_menu()
    assert target.target_type == "ip"
    assert target.ip == "10.48.159.132"
    assert target.mode == "Standard Recon"
    assert target.depth == "Common"

@patch("builtins.input", side_effect=["http://10.48.159.132", "2", "2"])
def test_interactive_menu_url_default_port(mock_input):
    target = interactive_menu()
    assert target.target_type == "url"
    assert target.ip == "10.48.159.132"
    assert target.port == 80
    assert target.mode == "WAF-Aware Low-Impact Recon"
    assert target.depth == "Medium"

@patch("builtins.input", side_effect=["https://example.com:8443", "1", "3"])
def test_interactive_menu_url_custom_port(mock_input):
    target = interactive_menu()
    assert target.target_type == "url"
    assert target.hostname == "example.com"
    assert target.port == 8443
    assert target.mode == "Standard Recon"
    assert target.depth == "Deep"

@patch("builtins.input", side_effect=KeyboardInterrupt)
def test_interactive_menu_keyboard_interrupt(mock_input):
    with pytest.raises(SystemExit) as excinfo:
        interactive_menu()
    assert excinfo.value.code == 0

