import os
from typing import Optional
from sentinelrecon.core.models import ReconTarget
from sentinelrecon.tools.adapters.base import BaseToolAdapter
from sentinelrecon.tools.models import ToolExecutionPlan


class NmapAdapter(BaseToolAdapter):
    def __init__(self):
        super().__init__("nmap")

    def supports_target(self, target: ReconTarget) -> bool:
        return target.target_type in ["ip", "network", "hostname"]

    def build_plan(self, target: ReconTarget, output_directory: str, mode: str = "Standard Recon", **kwargs) -> Optional[ToolExecutionPlan]:
        if not self.supports_target(target):
            return None

        output_file = os.path.join(output_directory, "nmap.xml")
        target_str = target.ip or target.hostname or target.input

        args = ["-sV"]
        if mode == "WAF-Aware Low-Impact Recon":
            args.extend(["-T2", "--max-rate", "50"])
        else:
            args.extend(["-T4"])

        args.extend(["-oX", output_file, target_str])

        return ToolExecutionPlan(
            tool="nmap",
            target=target_str,
            arguments=args,
            output_file=output_file
        )
