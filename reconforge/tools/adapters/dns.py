import os
from typing import Any

from reconforge.core.models import ReconTarget
from reconforge.tools.models import ToolExecutionPlan
from reconforge.tools.adapters.base import ToolAdapter

class DnsAdapter(ToolAdapter):
    @property
    def tool_name(self) -> str:
        return "dns_collector"

    @property
    def capability_name(self) -> str:
        return "DNS Record Analysis"

    @property
    def parser_name(self) -> str:
        return "DNSParser"

    def supports_target(self, target: ReconTarget) -> bool:
        if target.port == 53:
            return True
        if target.scheme and "dns" in target.scheme.lower():
            return True
        return False

    def build_plan(self, target: ReconTarget, output_dir: str, **kwargs: Any) -> ToolExecutionPlan:
        output_file = os.path.join(output_dir, f"dns_{target.hostname or target.ip}.txt")
        return ToolExecutionPlan(
            tool=self.tool_name,
            target=target.input,
            arguments=[target.hostname or target.ip],
            output_file=output_file
        )
