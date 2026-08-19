import os
import urllib.error
import socket
from unittest.mock import patch, MagicMock
from reconforge.tools.models import ToolExecutionPlan
from reconforge.tools.collectors import execute_http_collector, execute_tls_collector
from reconforge.core.config import ReconConfig

def test_http_collector_success(tmp_path):
    output_file = str(tmp_path / "headers.txt")
    plan = ToolExecutionPlan(tool="http_collector", target="http://example.com", arguments=["http://example.com"], output_file=output_file)
    config = ReconConfig()

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.getheaders.return_value = [("Server", "nginx")]
        mock_urlopen.return_value.__enter__.return_value = mock_response

        result = execute_http_collector(plan, config)

        assert result.success is True
        assert os.path.exists(output_file)
        with open(output_file, "r") as f:
            content = f.read()
            assert "HTTP/1.1 200 OK" in content
            assert "Server: nginx" in content

def test_http_collector_timeout(tmp_path):
    output_file = str(tmp_path / "headers.txt")
    plan = ToolExecutionPlan(tool="http_collector", target="http://example.com", arguments=["http://example.com"], output_file=output_file)
    config = ReconConfig()

    with patch("urllib.request.urlopen", side_effect=socket.timeout("timeout")):
        result = execute_http_collector(plan, config)

        assert result.success is False
        assert result.timed_out is True
        assert "Connection timed out" in result.error

def test_http_collector_url_error(tmp_path):
    output_file = str(tmp_path / "headers.txt")
    plan = ToolExecutionPlan(tool="http_collector", target="http://example.com", arguments=["http://example.com"], output_file=output_file)
    config = ReconConfig()

    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Not found")):
        result = execute_http_collector(plan, config)

        assert result.success is False
        assert result.timed_out is False
        assert "Not found" in result.error

def test_tls_collector_success(tmp_path):
    output_file = str(tmp_path / "tls.txt")
    plan = ToolExecutionPlan(tool="tls_collector", target="https://example.com", arguments=["https://example.com"], output_file=output_file)
    config = ReconConfig()

    with patch("socket.create_connection"), patch("ssl.create_default_context") as mock_ctx, patch("ssl.DER_cert_to_PEM_cert", return_value="PEM_DATA"):
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = b"der_data"
        mock_ctx.return_value.wrap_socket.return_value.__enter__.return_value = mock_ssock

        result = execute_tls_collector(plan, config)

        assert result.success is True
        assert os.path.exists(output_file)
        with open(output_file, "r") as f:
            assert f.read() == "PEM_DATA"

def test_tls_collector_timeout(tmp_path):
    output_file = str(tmp_path / "tls.txt")
    plan = ToolExecutionPlan(tool="tls_collector", target="https://example.com", arguments=["https://example.com"], output_file=output_file)
    config = ReconConfig()

    with patch("socket.create_connection", side_effect=socket.timeout("timeout")):
        result = execute_tls_collector(plan, config)

        assert result.success is False
        assert result.timed_out is True
