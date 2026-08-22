import os
import shutil
from typing import Any

from reconforge.core.models import ReconTarget
from reconforge.tools.models import ToolExecutionPlan
from reconforge.tools.adapters.base import ToolAdapter


class DNSAdapter(ToolAdapter):
    """Lightweight DNS/reverse-DNS collector using the system `host` utility."""

    @property
    def tool_name(self) -> str:
        return "dns_lookup"

    @property
    def parser_name(self) -> str:
        return "DNSParser"

    def supports_target(self, target: ReconTarget) -> bool:
        return bool(target.ip or target.hostname)

    def build_plan(self, target: ReconTarget, output_dir: str, **kwargs: Any) -> ToolExecutionPlan:
        output_file = os.path.join(output_dir, "dns.txt")
        lookup = target.hostname or target.ip
        return ToolExecutionPlan(
            tool=self.tool_name,
            target=target.input,
            arguments=[lookup],
            output_file=output_file,
        )

    @staticmethod
    def executable_available() -> bool:
        return shutil.which("host") is not None
