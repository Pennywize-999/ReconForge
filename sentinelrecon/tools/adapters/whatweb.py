import os
from typing import Optional
from sentinelrecon.core.models import ReconTarget
from sentinelrecon.tools.adapters.base import BaseToolAdapter
from sentinelrecon.tools.models import ToolExecutionPlan


class WhatWebAdapter(BaseToolAdapter):
    def __init__(self):
        super().__init__("whatweb")

    def supports_target(self, target: ReconTarget) -> bool:
        return target.target_type == "url"

    def build_plan(self, target: ReconTarget, output_directory: str, **kwargs) -> Optional[ToolExecutionPlan]:
        if not self.supports_target(target):
            return None

        output_file = os.path.join(output_directory, "whatweb.txt")
        args = [
            "-a", "1",
            "--color=never",
            "--log-brief=" + output_file,
            target.url
        ]

        if target.mode == "WAF-Aware Low-Impact Recon":
            args.extend(["-t", "1"])

        return ToolExecutionPlan(
            tool="whatweb",
            target=target.input,
            arguments=args,
            output_file=output_file
        )
