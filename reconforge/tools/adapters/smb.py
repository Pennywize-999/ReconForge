import os
from typing import Any

from reconforge.core.models import ReconTarget
from reconforge.tools.models import ToolExecutionPlan
from reconforge.tools.adapters.base import ToolAdapter

class SmbAdapter(ToolAdapter):
    @property
    def tool_name(self) -> str:
        return "smb_collector"

    @property
    def capability_name(self) -> str:
        return "SMB Share Enumeration"

    @property
    def parser_name(self) -> str:
        return "SMBParser"

    def supports_target(self, target: ReconTarget) -> bool:
        if target.port in [139, 445]:
            return True
        if target.scheme and "smb" in target.scheme.lower():
            return True
        return False

    def build_plan(self, target: ReconTarget, output_dir: str, **kwargs: Any) -> ToolExecutionPlan:
        output_file = os.path.join(output_dir, f"smb_{target.ip or target.hostname}.txt")
        return ToolExecutionPlan(
            tool=self.tool_name,
            target=target.input,
            arguments=[target.ip or target.hostname],
            output_file=output_file
        )
