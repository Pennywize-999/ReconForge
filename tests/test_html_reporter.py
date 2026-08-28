import os
import pytest
from reconforge.reporters.html import HTMLReporter
from reconforge.core.models import Target, Host

def test_html_reporter_resolves_template(tmp_path):
    reporter = HTMLReporter()
    assert reporter.env is not None
    
    # Try getting the template, should not crash
    template = reporter.env.get_template('report.html')
    assert template is not None

def test_html_reporter_generates_report(tmp_path):
    reporter = HTMLReporter()
    target = Target()
    target.hosts["127.0.0.1"] = Host(ip="127.0.0.1", status="up")
    
    output_file = tmp_path / "report.html"
    reporter.report(target, str(output_file))
    
    assert output_file.exists()
    content = output_file.read_text(encoding="utf-8")
    assert "127.0.0.1" in content

def test_html_reporter_different_cwd(tmp_path):
    original_cwd = os.getcwd()
    try:
        os.chdir(str(tmp_path))
        reporter = HTMLReporter()
        target = Target()
        reporter.report(target, "test_report.html")
        assert os.path.exists("test_report.html")
    finally:
        os.chdir(original_cwd)

def test_html_reporter_package_availability():
    try:
        from importlib import resources
        if hasattr(resources, 'files'):
            template_path = resources.files('reconforge.templates').joinpath('report.html')
            assert template_path.is_file()
    except ImportError:
        pass
