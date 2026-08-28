import json
from sentinelrecon.core.models import ModelEncoder, Target


class JSONReporter:
    def report(self, target: Target, output_path: str):
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(target, f, cls=ModelEncoder, indent=2)
