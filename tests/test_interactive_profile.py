from sentinelrecon.interactive import interactive_menu


def test_interactive_url_default_port_and_autonomous_profile(monkeypatch):
    answers = iter(["http://127.0.0.1", "1", "1"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    target = interactive_menu()

    assert target.url == "http://127.0.0.1:80"
    assert target.port == 80
    assert target.mode == "Standard Recon"
    assert target.discovery_profile == "AUTONOMOUS"
    assert target.source == "interactive_execute"
