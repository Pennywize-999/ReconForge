import os
from typing import Any

from reconforge.core.models import ReconTarget
from reconforge.tools.models import ToolExecutionPlan
from reconforge.tools.adapters.base import ToolAdapter

class TlsCollectorAdapter(ToolAdapter):
    @property
    def tool_name(self) -> str:
        return "tls_collector"

    @property
    def capability_name(self) -> str:
        return "TLS Certificate Inspection"


    @property
    def parser_name(self) -> str:
        return "TLSParser"

    def supports_target(self, target: ReconTarget) -> bool:
        return target.scheme == "https"

    def build_plan(self, target: ReconTarget, output_dir: str, **kwargs: Any) -> ToolExecutionPlan:
        output_file = os.path.join(output_dir, "tls.txt")
        return ToolExecutionPlan(
            tool=self.tool_name,
            target=target.input,
            arguments=[target.url],
            output_file=output_file
        )
