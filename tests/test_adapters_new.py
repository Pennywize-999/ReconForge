import os
from unittest.mock import patch
from reconforge.core.target_parser import parse_target
from reconforge.tools.adapters.dirb import DirbAdapter
from reconforge.tools.adapters.http_collector import HttpCollectorAdapter
from reconforge.tools.adapters.tls_collector import TlsCollectorAdapter
from reconforge.core.config import ReconConfig

def test_dirb_adapter():
    adapter = DirbAdapter()
    target = parse_target("http://127.0.0.1")
    assert adapter.supports_target(target) is True

    target_ip = parse_target("127.0.0.1")
    assert adapter.supports_target(target_ip) is False

    with patch("reconforge.tools.adapters.dirb.load_config") as mock_cfg, patch("os.path.exists", return_value=True):
        mock_cfg.return_value = ReconConfig(default_wordlists=["/usr/share/wordlists/dirb/common.txt"])
        plan = adapter.build_plan(target, "/out")
        assert plan is not None
        assert plan.tool == "dirb"
        assert "-S" in plan.arguments

def test_dirb_adapter_no_wordlist():
    adapter = DirbAdapter()
    target = parse_target("http://127.0.0.1")
    with patch("reconforge.tools.adapters.dirb.load_config") as mock_cfg, patch("os.path.exists", return_value=False):
        mock_cfg.return_value = ReconConfig(default_wordlists=["/usr/share/wordlists/dirb/common.txt"])
        plan = adapter.build_plan(target, "/out")
        assert plan is None

def test_http_collector_adapter():
    adapter = HttpCollectorAdapter()
    target = parse_target("http://127.0.0.1")
    assert adapter.supports_target(target) is True

    target_ip = parse_target("127.0.0.1")
    assert adapter.supports_target(target_ip) is False

    plan = adapter.build_plan(target, "/out")
    assert plan.tool == "http_collector"
    assert "headers.txt" in plan.output_file

def test_tls_collector_adapter():
    adapter = TlsCollectorAdapter()
    target = parse_target("https://127.0.0.1")
    assert adapter.supports_target(target) is True

    target_http = parse_target("http://127.0.0.1")
    assert adapter.supports_target(target_http) is False

    plan = adapter.build_plan(target, "/out")
    assert plan.tool == "tls_collector"
    assert "tls.txt" in plan.output_file
