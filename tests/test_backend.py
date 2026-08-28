import os
from unittest.mock import patch
from reconforge.core.target_parser import parse_target
from reconforge.core.planner import ReconPlanner
from reconforge.execution.backend import PlanningOnlyBackend, RealExecutionBackend

def test_planning_backend():
    target = parse_target("127.0.0.1")
    planner = ReconPlanner()
    plan = planner.plan(target)

    backend = PlanningOnlyBackend()
    # It just prints, shouldn't crash
    result = backend.execute(plan)
    assert result is None

@patch("reconforge.execution.executor.ToolExecutor.execute")
@patch("reconforge.core.analyzer.Analyzer.analyze_directory")
def test_real_execution_backend(mock_analyze, mock_execute, tmp_path):
    target = parse_target("127.0.0.1")
    planner = ReconPlanner()
    plan = planner.plan(target)
    plan.output_directory = str(tmp_path)

    # Mock executor result
    from reconforge.execution.executor import ToolExecutionResult
    mock_execute.return_value = ToolExecutionResult(
        tool="nmap",
        target="127.0.0.1",
        arguments=[],
        output_file="",
        return_code=0,
        stdout="",
        stderr="",
        started_at="",
        finished_at="",
        duration=0.0,
        success=True,
        timed_out=False,
        error=""
    )

    from reconforge.core.models import Target
    analyzed_target = Target()
    mock_analyze.return_value = analyzed_target

    backend = RealExecutionBackend()

    with patch("reconforge.tools.registry.ToolRegistry.is_installed", return_value=True):
        result = backend.execute(plan)

    assert result == analyzed_target
    assert mock_execute.called
    assert mock_analyze.called
