import pytest
from sentinelrecon.core.models import ReconTarget
from sentinelrecon.core.planner import ReconPlanner


def test_planner_ip_target():
    target = ReconTarget(input="10.48.159.132", target_type="ip", ip="10.48.159.132", mode="Standard Recon")
    planner = ReconPlanner()
    plan = planner.plan(target)

    assert plan.mode == "Standard Recon"
    assert "Network Discovery" in plan.modules
    assert "Service Analysis" in plan.modules
    assert "Adaptive Discovery" in plan.modules
    assert "Vulnerability Assessment" in plan.modules
    assert not any("Forge" in m for m in plan.modules)
    assert plan.metadata.get("respect_rate_limits") is False


def test_planner_url_target():
    target = ReconTarget(input="https://example.com", target_type="url", hostname="example.com", scheme="https", port=443, mode="Standard Recon")
    planner = ReconPlanner()
    plan = planner.plan(target)

    assert "Web Analysis" in plan.modules
    assert "Technology Detection" in plan.modules
    assert "TLS Analysis" in plan.modules
    assert not any("Forge" in m for m in plan.modules)


def test_planner_waf_aware_mode():
    target = ReconTarget(input="http://10.48.159.132", target_type="url", ip="10.48.159.132", scheme="http", port=80, mode="WAF-Aware Low-Impact Recon")
    planner = ReconPlanner()
    plan = planner.plan(target)

    assert plan.mode == "WAF-Aware Low-Impact Recon"
    assert plan.metadata.get("respect_rate_limits") is True
    assert plan.metadata.get("respect_retry_after") is True
    assert plan.metadata.get("avoid_duplicate_requests") is True
    assert plan.metadata.get("evasion_techniques") is False
