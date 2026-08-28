import os
from typing import Optional, Set
from sentinelrecon.core.discovery import DiscoveryProfileComposer, get_discovery_profile
from sentinelrecon.core.models import ReconTarget
from sentinelrecon.tools.adapters.base import BaseToolAdapter
from sentinelrecon.tools.models import ToolExecutionPlan


class DirbAdapter(BaseToolAdapter):
    def __init__(self):
        super().__init__("dirb")
        self.composer = DiscoveryProfileComposer()

    def supports_target(self, target: ReconTarget) -> bool:
        return target.target_type == "url"

    def build_plan(self, target: ReconTarget, output_directory: str, **kwargs) -> Optional[ToolExecutionPlan]:
        if not self.supports_target(target):
            return None

        output_file = os.path.join(output_directory, "dirb.txt")
        profile_name = target.discovery_profile or "COMMON"
        technologies = kwargs.get("technologies") or set()
        custom_candidates = kwargs.get("custom_candidates") or []

        wordlist_path, active_techs, extensions = self.composer.write_composite_wordlist(
            output_directory,
            depth=profile_name,
            technologies=technologies,
            custom_candidates=custom_candidates,
        )

        args = [
            target.url,
            wordlist_path,
            "-o", output_file,
            "-r",
            "-S",
            "-w"
        ]

        if target.mode == "WAF-Aware Low-Impact Recon":
            args.extend(["-z", "100"])

        return ToolExecutionPlan(
            tool="dirb",
            target=target.input,
            arguments=args,
            output_file=output_file
        )
