import os
from typing import Optional
from sentinelrecon.core.models import ReconTarget
from sentinelrecon.tools.adapters.base import BaseToolAdapter
from sentinelrecon.tools.models import ToolExecutionPlan


class DNSAdapter(BaseToolAdapter):
    def __init__(self):
        super().__init__("dns_lookup")

    def supports_target(self, target: ReconTarget) -> bool:
        return target.target_type in ["ip", "hostname", "url"]

    def build_plan(self, target: ReconTarget, output_directory: str, **kwargs) -> Optional[ToolExecutionPlan]:
        if not self.supports_target(target):
            return None

        output_file = os.path.join(output_directory, "dns.txt")
        query_target = target.hostname or target.ip or target.input
        if target.target_type == "url" and target.hostname:
            query_target = target.hostname

        return ToolExecutionPlan(
            tool="host",
            target=query_target,
            arguments=[query_target],
            output_file=output_file
        )
