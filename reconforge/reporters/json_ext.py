import json
from reconforge.core.models import Target, ModelEncoder

class JSONReporter:
    def report(self, target: Target, output_file: str):
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(target, f, cls=ModelEncoder, indent=2)
