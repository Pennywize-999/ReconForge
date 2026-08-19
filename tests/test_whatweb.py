from reconforge.core.models import ReconTarget
from reconforge.tools.adapters.whatweb import WhatWebAdapter
from reconforge.tools.registry import ToolRegistry

def test_whatweb_adapter_target_support():
    adapter = WhatWebAdapter()
    
    target_http = ReconTarget(input="http://example.com", target_type="url", scheme="http", url="http://example.com")
    assert adapter.supports_target(target_http)
    
    target_https = ReconTarget(input="https://example.com", target_type="url", scheme="https", url="https://example.com")
    assert adapter.supports_target(target_https)
    
    target_ip = ReconTarget(input="10.10.10.10", target_type="ip", ip="10.10.10.10")
    assert not adapter.supports_target(target_ip)

def test_whatweb_plan_generation():
    adapter = WhatWebAdapter()
    target = ReconTarget(input="http://example.com", target_type="url", scheme="http", url="http://example.com")
    plan = adapter.build_plan(target, "out")
    
    assert plan.tool == "whatweb"
    assert plan.target == "http://example.com"
    assert "http://example.com" in plan.arguments

def test_registry_registration():
    registry = ToolRegistry()
    tool = registry.get_tool("whatweb")
    assert tool is not None
    assert tool.name == "whatweb"
    assert tool.category == "Web"
