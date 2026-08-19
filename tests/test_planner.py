import pytest
from reconforge.core.models import ReconTarget
from reconforge.core.planner import ReconPlanner

def test_planner_ip_target():
    target = ReconTarget(input="10.48.159.132", target_type="ip", ip="10.48.159.132", mode="Standard Recon")
    planner = ReconPlanner()
    plan = planner.plan(target)

    assert plan.mode == "Standard Recon"
    assert "Network Analysis (Nmap)" in plan.modules
    assert plan.metadata.get("respect_rate_limits") == False

def test_planner_url_target():
    target = ReconTarget(input="https://example.com", target_type="url", hostname="example.com", scheme="https", port=443, mode="Standard Recon")
    planner = ReconPlanner()
    plan = planner.plan(target)

    assert "Web Analysis" in plan.modules
    assert "TLS Analysis" in plan.modules

def test_planner_waf_aware_mode():
    target = ReconTarget(input="http://10.48.159.132", target_type="url", ip="10.48.159.132", scheme="http", port=80, mode="WAF-Aware Low-Impact Recon")
    planner = ReconPlanner()
    plan = planner.plan(target)

    assert plan.mode == "WAF-Aware Low-Impact Recon"
    assert plan.metadata.get("respect_rate_limits") == True
    assert plan.metadata.get("respect_retry_after") == True
    assert plan.metadata.get("avoid_duplicate_requests") == True
    assert plan.metadata.get("evasion_techniques") == False
