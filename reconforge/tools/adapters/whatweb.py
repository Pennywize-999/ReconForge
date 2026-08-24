import os
from typing import Any

from reconforge.core.models import ReconTarget
from reconforge.tools.models import ToolExecutionPlan
from reconforge.tools.adapters.base import ToolAdapter


class WhatWebAdapter(ToolAdapter):
    @property
    def tool_name(self) -> str:
        return "whatweb"

    @property
    def parser_name(self) -> str:
        return "WhatWebParser"

    def supports_target(self, target: ReconTarget) -> bool:
        return target.scheme in ["http", "https"]

    def build_plan(self, target: ReconTarget, output_dir: str, **kwargs: Any) -> ToolExecutionPlan:
        output_file = os.path.join(output_dir, f"{self.tool_name}.txt")
        profile = str(kwargs.get("discovery_profile") or getattr(target, "discovery_profile", "COMMON")).upper()

        # COMMON/EXTENDED use WhatWeb's passive/stealthy level so application
        # fingerprinting is part of normal reconnaissance without turning one
        # slow target into a long-running scan. DEEP keeps aggressive matching.
        aggression = "3" if profile == "DEEP" else "1"
        threads = "3" if profile == "DEEP" else "1"

        args = [
            "-a", aggression,
            "-t", threads,
            "--open-timeout", "5",
            "--read-timeout", "10",
            target.url,
            "--log-brief", output_file,
        ]

        return ToolExecutionPlan(
            tool=self.tool_name,
            target=target.input,
            arguments=args,
            output_file=output_file,
        )
