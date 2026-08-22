from reconforge.interactive import interactive_menu


def test_interactive_url_default_port_and_deep_profile(monkeypatch):
    answers = iter(["http://127.0.0.1", "", "1", "3"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    target = interactive_menu()

    assert target.url == "http://127.0.0.1:80"
    assert target.port == 80
    assert target.mode == "Standard Recon"
    assert target.discovery_profile == "DEEP"
    assert target.source == "interactive_execute"
