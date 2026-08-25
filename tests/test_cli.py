import sys
from unittest.mock import patch, MagicMock
import pytest
from reconforge.cli import main

def test_cli_plan_flag_uses_planning_backend():
    with patch("sys.argv", ["reconforge", "127.0.0.1", "--plan"]), \
         patch("reconforge.cli.PlanningOnlyBackend") as mock_plan_backend, \
         patch("reconforge.execution.backend.RealExecutionBackend") as mock_real_backend:
        
        mock_plan_backend.return_value.execute.return_value = None
        
        with pytest.raises(SystemExit) as e:
            main()
            
        assert e.value.code == 0
        mock_plan_backend.assert_called_once()
        mock_real_backend.assert_not_called()

def test_cli_default_uses_real_backend():
    with patch("sys.argv", ["reconforge", "127.0.0.1"]), \
         patch("reconforge.cli.PlanningOnlyBackend") as mock_plan_backend, \
         patch("reconforge.execution.backend.RealExecutionBackend") as mock_real_backend, \
         patch("reconforge.reporters.terminal.TerminalReporter"):
        
        mock_real_backend.return_value.execute.return_value = None
        
        with pytest.raises(SystemExit) as e:
            main()
            
        assert e.value.code == 0
        mock_real_backend.assert_called_once()
        mock_plan_backend.assert_not_called()

def test_cli_execute_flag_uses_real_backend():
    with patch("sys.argv", ["reconforge", "127.0.0.1", "--execute"]), \
         patch("reconforge.cli.PlanningOnlyBackend") as mock_plan_backend, \
         patch("reconforge.execution.backend.RealExecutionBackend") as mock_real_backend, \
         patch("reconforge.reporters.terminal.TerminalReporter"):
        
        mock_real_backend.return_value.execute.return_value = None
        
        with pytest.raises(SystemExit) as e:
            main()
            
        assert e.value.code == 0
        mock_real_backend.assert_called_once()
        mock_plan_backend.assert_not_called()

def test_cli_interactive_default_uses_real_backend():
    with patch("sys.argv", ["reconforge"]), \
         patch("reconforge.cli.interactive_menu") as mock_menu, \
         patch("reconforge.cli.PlanningOnlyBackend") as mock_plan_backend, \
         patch("reconforge.execution.backend.RealExecutionBackend") as mock_real_backend, \
         patch("reconforge.reporters.terminal.TerminalReporter"):
         
        from reconforge.core.models import ReconTarget
        mock_menu.return_value = ReconTarget(input="127.0.0.1", target_type="ip", ip="127.0.0.1")
        mock_real_backend.return_value.execute.return_value = None
        
        with pytest.raises(SystemExit) as e:
            main()
            
        assert e.value.code == 0
        mock_real_backend.assert_called_once()
        mock_plan_backend.assert_not_called()
