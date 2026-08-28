import os
from typing import Optional, Set
from sentinelrecon.core.discovery import DiscoveryProfileComposer, get_discovery_profile
from sentinelrecon.core.models import ReconTarget
from sentinelrecon.tools.adapters.base import BaseToolAdapter
from sentinelrecon.tools.models import ToolExecutionPlan


class GobusterAdapter(BaseToolAdapter):
    def __init__(self):
        super().__init__("gobuster")
        self.composer = DiscoveryProfileComposer()

    def supports_target(self, target: ReconTarget) -> bool:
        return target.target_type == "url"

    def build_plan(self, target: ReconTarget, output_directory: str, **kwargs) -> Optional[ToolExecutionPlan]:
        if not self.supports_target(target):
            return None

        output_file = os.path.join(output_directory, "gobuster.txt")
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
            "dir",
            "-u", target.url,
            "-w", wordlist_path,
            "-o", output_file,
            "-k",
            "-q",
        ]

        if extensions:
            exts = ",".join([e.lstrip(".") for e in extensions[:12]])
            args.extend(["-x", exts])

        if target.mode == "WAF-Aware Low-Impact Recon":
            args.extend(["-t", "2", "--delay", "150ms"])
        else:
            args.extend(["-t", "10"])

        return ToolExecutionPlan(
            tool="gobuster",
            target=target.input,
            arguments=args,
            output_file=output_file
        )
