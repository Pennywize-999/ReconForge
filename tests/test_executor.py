import os
import subprocess
import pytest
from unittest.mock import patch, MagicMock
from reconforge.tools.models import ToolExecutionPlan
from reconforge.execution.executor import ToolExecutor

def test_executor_success():
    executor = ToolExecutor()
    plan = ToolExecutionPlan(tool="echo", target="127.0.0.1", arguments=["hello"], output_file="")

    with patch("subprocess.run") as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "hello\n"
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        result = executor.execute(plan)

        assert result.success is True
        assert result.return_code == 0
        assert result.stdout == "hello\n"
        assert not result.timed_out
        assert not result.error

def test_executor_timeout():
    executor = ToolExecutor()
    plan = ToolExecutionPlan(tool="sleep", target="127.0.0.1", arguments=["10"], output_file="")

    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["sleep", "10"], timeout=300, output=b"partial", stderr=b"")

        result = executor.execute(plan)

        assert result.success is False
        assert result.timed_out is True
        assert "Timed out" in result.error
        assert result.stdout == "partial"

def test_executor_not_found():
    executor = ToolExecutor()
    plan = ToolExecutionPlan(tool="missing_tool", target="127.0.0.1", arguments=[], output_file="")

    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = FileNotFoundError()

        result = executor.execute(plan)

        assert result.success is False
        assert "Executable not found" in result.error

def test_executor_failure():
    executor = ToolExecutor()
    plan = ToolExecutionPlan(tool="false", target="127.0.0.1", arguments=[], output_file="")

    with patch("subprocess.run") as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "error message"
        mock_run.return_value = mock_result

        result = executor.execute(plan)

        assert result.success is False
        assert result.return_code == 1
        assert "Command failed" in result.error
        assert result.stderr == "error message"
