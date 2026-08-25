import json
import dataclasses
from reconforge.core.models import ReconPlan, ReconTarget

def test_recon_plan_serialization():
    target = ReconTarget(
        input="127.0.0.1",
        target_type="ip",
        ip="127.0.0.1",
        depth="Deep"
    )
    plan = ReconPlan(
        mode="Standard Recon",
        target=target,
        depth="Deep",
        modules=["Network Discovery"],
        output_directory="/tmp",
        metadata={"key": "value"}
    )

    # Serialize
    plan_dict = dataclasses.asdict(plan)
    json_str = json.dumps(plan_dict)

    # Deserialize back
    loaded_dict = json.loads(json_str)

    assert loaded_dict["mode"] == "Standard Recon"
    assert loaded_dict["depth"] == "Deep"
    assert loaded_dict["target"]["ip"] == "127.0.0.1"
    assert loaded_dict["target"]["depth"] == "Deep"
    assert loaded_dict["target"]["target_type"] == "ip"
    assert loaded_dict["modules"] == ["Network Discovery"]
    assert loaded_dict["metadata"]["key"] == "value"

    # Test from_dict methods
    target_obj = ReconTarget.from_dict(loaded_dict["target"])
    assert target_obj.depth == "Deep"

    plan_obj = ReconPlan.from_dict(loaded_dict)
    assert plan_obj.depth == "Deep"
    assert plan_obj.target.depth == "Deep"

