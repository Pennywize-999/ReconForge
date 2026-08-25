import pytest
from reconforge.core.target_parser import parse_target
from reconforge.core.planner import ReconPlanner
from reconforge.tools.adapters.nmap import NmapAdapter
from reconforge.tools.adapters.gobuster import GobusterAdapter
from reconforge.tools.adapters.whatweb import WhatWebAdapter

def test_target_depth_parsing():
    t_common = parse_target("10.0.2.14", depth="Common")
    assert t_common.depth == "Common"

    t_medium = parse_target("http://10.0.2.14", depth="Medium")
    assert t_medium.depth == "Medium"

    t_deep = parse_target("https://10.0.2.14:8443", depth="Deep")
    assert t_deep.depth == "Deep"

def test_planner_incorporates_depth():
    target = parse_target("10.0.2.14", depth="Deep")
    planner = ReconPlanner()
    plan = planner.plan(target)
    assert plan.depth == "Deep"
    assert plan.metadata.get("depth") == "Deep"

def test_nmap_depth_arguments():
    adapter = NmapAdapter()
    
    t_common = parse_target("10.0.2.14", depth="Common")
    plan_common = adapter.build_plan(t_common, "scratch/tmp")
    assert "-F" in plan_common.arguments

    t_medium = parse_target("10.0.2.14", depth="Medium")
    plan_medium = adapter.build_plan(t_medium, "scratch/tmp")
    assert "-sC" in plan_medium.arguments
    assert "-F" not in plan_medium.arguments

    t_deep = parse_target("10.0.2.14", depth="Deep")
    plan_deep = adapter.build_plan(t_deep, "scratch/tmp")
    assert "-p-" in plan_deep.arguments
    assert "-sC" in plan_deep.arguments

def test_gobuster_depth_arguments():
    adapter = GobusterAdapter()

    t_medium = parse_target("http://10.0.2.14", depth="Medium")
    plan_med = adapter.build_plan(t_medium, "scratch/tmp")
    if plan_med:
        assert "-x" in plan_med.arguments
        assert "php,html,txt" in plan_med.arguments

    t_deep = parse_target("http://10.0.2.14", depth="Deep")
    plan_deep = adapter.build_plan(t_deep, "scratch/tmp")
    if plan_deep:
        assert "-x" in plan_deep.arguments
        assert "php,html,txt,json,xml,bak,zip" in plan_deep.arguments

def test_whatweb_depth_aggression():
    adapter = WhatWebAdapter()

    t_common = parse_target("http://10.0.2.14", depth="Common")
    plan_common = adapter.build_plan(t_common, "scratch/tmp")
    assert plan_common.arguments[1] == "1"

    t_medium = parse_target("http://10.0.2.14", depth="Medium")
    plan_med = adapter.build_plan(t_medium, "scratch/tmp")
    assert plan_med.arguments[1] == "3"
