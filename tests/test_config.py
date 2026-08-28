import os
from reconforge.core.config import ReconConfig, load_config

def test_default_config():
    config = ReconConfig()
    assert config.timeout == 300
    assert config.gobuster_threads == 10
    assert "common.txt" in config.default_wordlists[0]

def test_load_config_no_file(monkeypatch):
    monkeypatch.setattr("os.path.exists", lambda x: False)
    config = load_config()
    assert config.timeout == 300
