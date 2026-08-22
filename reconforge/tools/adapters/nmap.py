import os
from typing import Any

from reconforge.core.models import ReconTarget
from reconforge.tools.models import ToolExecutionPlan
from reconforge.tools.adapters.base import ToolAdapter


class NmapAdapter(ToolAdapter):
    @property
    def tool_name(self) -> str:
        return "nmap"

    @property
    def parser_name(self) -> str:
        return "NmapXMLParser"

    def supports_target(self, target: ReconTarget) -> bool:
        # Nmap is primarily for IP/Hostname, but we can extract it from URL.
        return target.ip is not None or target.hostname is not None

    def build_plan(self, target: ReconTarget, output_dir: str, **kwargs: Any) -> ToolExecutionPlan:
        output_file = os.path.join(output_dir, f"{self.tool_name}.xml")
        mode = str(kwargs.get("mode", target.mode)).lower()
        specific_port = target.port is not None

        # STANDARD is the complete first-level discovery pass. LOW-IMPACT keeps
        # the safer top-port profile while preserving service/version detection.
        if specific_port:
            args = ["-sV", "-sC", "-oX", output_file, "-p", str(target.port)]
        elif "low-impact" in mode or "low impact" in mode:
            args = ["-sV", "-sC", "--top-ports", "1000", "-oX", output_file]
        else:
            args = ["-A", "-p-", "-oX", output_file]

        args.append(target.ip if target.ip else target.hostname)

        return ToolExecutionPlan(
            tool=self.tool_name,
            target=target.input,
            arguments=args,
            output_file=output_file,
        )
