import pytest
from unittest.mock import patch, MagicMock
from reconforge.core.target_parser import parse_target
from reconforge.core.planner import ReconPlanner
from reconforge.execution.backend import RealExecutionBackend
from reconforge.core.models import Target, Host, Port, Service

@patch("reconforge.execution.executor.ToolExecutor.execute")
@patch("reconforge.core.analyzer.Analyzer.analyze_directory")
def test_two_phase_execution_triggers_web_tools(mock_analyze, mock_execute, tmp_path):
    target = parse_target("127.0.0.1")
    planner = ReconPlanner()
    plan = planner.plan(target)
    plan.output_directory = str(tmp_path)

    # Mock first phase result (Nmap discovered port 80)
    analyzed_target = Target()
    host = Host(ip="127.0.0.1", status="up")
    host.ports.append(Port(number=80, protocol="tcp", state="open", service=Service(name="http")))
    analyzed_target.hosts["127.0.0.1"] = host
    
    mock_analyze.return_value = analyzed_target

    from reconforge.execution.executor import ToolExecutionResult
    mock_execute.return_value = ToolExecutionResult(
        tool="mocked", target="mocked", arguments=[], output_file="",
        return_code=0, stdout="", stderr="", started_at="", finished_at="",
        duration=0.0, success=True, timed_out=False, error=""
    )

    backend = RealExecutionBackend()

    import os
    original_exists = os.path.exists

    def fake_exists(path):
        if "wordlists" in str(path):
            return True
        return original_exists(path)

    with patch("reconforge.tools.registry.ToolRegistry.is_installed", return_value=True), \
         patch("os.path.exists", side_effect=fake_exists):  # For wordlists
        
        result = backend.execute(plan)

    assert result == analyzed_target
    
    # Assert that executor was called multiple times (Nmap + Web tools)
    # nmap, gobuster, whatweb, dirb, http_collector, tls_collector(skipped for http)
    assert mock_execute.call_count > 1
    
    # Verify that whatweb was called for the constructed URL
    tools_called = [call.args[0].tool for call in mock_execute.call_args_list]
    assert "nmap" in tools_called
    assert "whatweb" in tools_called
    assert "http_collector" in tools_called

@patch("reconforge.execution.executor.ToolExecutor.execute")
@patch("reconforge.core.analyzer.Analyzer.analyze_directory")
def test_web_service_detection(mock_analyze, mock_execute, tmp_path):
    target = parse_target("127.0.0.1")
    planner = ReconPlanner()
    plan = planner.plan(target)
    plan.output_directory = str(tmp_path)

    analyzed_target = Target()
    host = Host(ip="127.0.0.1", status="up")
    
    # 80/http -> HTTP
    host.ports.append(Port(number=80, protocol="tcp", state="open", service=None))
    # 443/https -> HTTPS
    host.ports.append(Port(number=443, protocol="tcp", state="open", service=None))
    # 8080/http -> HTTP
    host.ports.append(Port(number=8080, protocol="tcp", state="open", service=None))
    # 8443/https -> HTTPS
    host.ports.append(Port(number=8443, protocol="tcp", state="open", service=None))
    # Arbitrary port identified as http
    host.ports.append(Port(number=9999, protocol="tcp", state="open", service=Service(name="http-proxy")))
    # SSH -> no web
    host.ports.append(Port(number=22, protocol="tcp", state="open", service=Service(name="ssh")))
    # SMTP -> no web
    host.ports.append(Port(number=25, protocol="tcp", state="open", service=Service(name="smtp")))
    
    analyzed_target.hosts["127.0.0.1"] = host
    mock_analyze.return_value = analyzed_target

    from reconforge.execution.executor import ToolExecutionResult
    mock_execute.return_value = ToolExecutionResult(
        tool="mocked", target="mocked", arguments=[], output_file="",
        return_code=0, stdout="", stderr="", started_at="", finished_at="",
        duration=0.0, success=True, timed_out=False, error=""
    )

    backend = RealExecutionBackend()
    import os
    original_exists = os.path.exists
    def fake_exists(path):
        if "wordlists" in str(path):
            return True
        return original_exists(path)

    with patch("reconforge.tools.registry.ToolRegistry.is_installed", return_value=True), \
         patch("os.path.exists", side_effect=fake_exists):
        backend.execute(plan)

    urls_scanned = [call.args[0].target for call in mock_execute.call_args_list if call.args[0].tool != "nmap"]
    
    assert "http://127.0.0.1:80" in urls_scanned
    assert "https://127.0.0.1:443" in urls_scanned
    assert "http://127.0.0.1:8080" in urls_scanned
    assert "https://127.0.0.1:8443" in urls_scanned
    assert "http://127.0.0.1:9999" in urls_scanned
    
    # Ensure non-web ports are not scanned
    assert not any("127.0.0.1:22" in url for url in urls_scanned)
    assert not any("127.0.0.1:25" in url for url in urls_scanned)
