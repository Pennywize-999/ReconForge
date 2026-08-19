import os
import json
from reconforge.core.analyzer import Analyzer
from reconforge.core.models import Target
from reconforge.reporters.terminal import TerminalReporter
from unittest.mock import patch, MagicMock

def test_analyzer_ignores_metadata(tmp_path):
    metadata_files = ["plan.json", "target.json", "execution.json", "report.json", "report.html"]
    for filename in metadata_files:
        path = tmp_path / filename
        path.write_text("{}")

    analyzer = Analyzer()
    target = analyzer.analyze_directory(str(tmp_path))

    assert len(target.evidence) == 0

def test_analyzer_parses_real_evidence(tmp_path):
    nmap_file = tmp_path / "nmap.xml"
    nmap_file.write_text("<?xml version=\"1.0\"?><nmaprun></nmaprun>")

    analyzer = Analyzer()
    target = analyzer.analyze_directory(str(tmp_path))

    assert len(target.evidence) == 1
    assert "NmapXMLParser" in target.evidence[0].source_type

def test_terminal_reporter_no_evidence(capsys):
    target = Target()
    reporter = TerminalReporter()

    # We mock console.print to capture output cleanly for rich
    with patch.object(reporter.console, "print") as mock_print:
        reporter._print_evidence_section(target)
        # Verify the empty evidence message was printed
        calls = mock_print.call_args_list
        found = any("No reconnaissance evidence was collected" in str(call) for call in calls)
        assert found
