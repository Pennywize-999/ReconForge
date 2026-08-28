import os
from typing import Optional
from sentinelrecon.core.models import ReconTarget
from sentinelrecon.tools.adapters.base import BaseToolAdapter
from sentinelrecon.tools.models import ToolExecutionPlan


class HttpCollectorAdapter(BaseToolAdapter):
    def __init__(self):
        super().__init__("http_collector")

    def supports_target(self, target: ReconTarget) -> bool:
        return target.target_type == "url"

    def build_plan(self, target: ReconTarget, output_directory: str, **kwargs) -> Optional[ToolExecutionPlan]:
        if not self.supports_target(target):
            return None

        output_file = os.path.join(output_directory, "headers.txt")
        return ToolExecutionPlan(
            tool="http_collector",
            target=target.input,
            arguments=[target.url],
            output_file=output_file
        )
