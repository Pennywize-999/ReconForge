import json
import dataclasses
from reconforge.core.models import ReconPlan, ReconTarget

def test_recon_plan_serialization():
    target = ReconTarget(
        input="127.0.0.1",
        target_type="ip",
        ip="127.0.0.1"
    )
    plan = ReconPlan(
        mode="Standard Recon",
        target=target,
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
    assert loaded_dict["target"]["ip"] == "127.0.0.1"
    assert loaded_dict["target"]["target_type"] == "ip"
    assert loaded_dict["modules"] == ["Network Discovery"]
    assert loaded_dict["metadata"]["key"] == "value"
