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
        # Nmap is primarily for IP/Hostname, but we can extract it from URL
        return target.ip is not None or target.hostname is not None

    def build_plan(self, target: ReconTarget, output_dir: str, **kwargs: Any) -> ToolExecutionPlan:
        output_file = os.path.join(output_dir, f"{self.tool_name}.xml")
        depth = getattr(target, "depth", "Common")
        mode = getattr(target, "mode", "Standard Recon")

        args = ["-sV"]

        if depth == "Common":
            args.extend(["-F"]) # Fast top ports scan
        elif depth == "Medium":
            args.extend(["-sC"]) # Top 1000 ports + default scripts
        elif depth == "Deep":
            args.extend(["-p-", "-sC"]) # All ports scan + default scripts
        else:
            args.extend(["-sC"])

        if mode == "WAF-Aware Low-Impact Recon":
            args.extend(["-T2", "--max-retries", "1"])

        args.extend(["-oX", output_file])

        # If it's a specific port (like from a URL), only scan that port
        if target.port:
            # Override port args if specific port specified
            if "-p-" in args:
                args.remove("-p-")
            if "-F" in args:
                args.remove("-F")
            args.extend(["-p", str(target.port)])

        args.append(target.ip if target.ip else target.hostname)

        return ToolExecutionPlan(
            tool=self.tool_name,
            target=target.input,
            arguments=args,
            output_file=output_file
        )

