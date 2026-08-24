import os
from typing import Any, Optional

from reconforge.core.models import ReconTarget
from reconforge.tools.models import ToolExecutionPlan
from reconforge.tools.adapters.base import ToolAdapter
from reconforge.core.config import load_config


class DirbAdapter(ToolAdapter):
    @property
    def tool_name(self) -> str:
        return "dirb"

    @property
    def parser_name(self) -> str:
        return "DirbParser"

    def supports_target(self, target: ReconTarget) -> bool:
        return target.scheme in ["http", "https"]

    def build_plan(self, target: ReconTarget, output_dir: str, **kwargs: Any) -> Optional[ToolExecutionPlan]:
        config = load_config()
        profile = kwargs.get("discovery_profile") or getattr(target, "discovery_profile", "COMMON")
        technologies = kwargs.get("technologies", [])
        services = kwargs.get("services", [])

        try:
            from reconforge.core.discovery import DiscoveryEngine
            discovery = DiscoveryEngine().build(profile, technologies=technologies, services=services)
        except Exception:
            discovery = None

        generated = os.path.join(output_dir, f"reconforge_{profile.lower()}_wordlist.txt")
        if discovery and discovery.candidates:
            try:
                os.makedirs(output_dir, exist_ok=True)
                with open(generated, "w", encoding="utf-8") as handle:
                    for candidate in discovery.candidates:
                        handle.write(candidate.path + "\n")
            except (OSError, PermissionError):
                generated = ""

        fallback = config.default_wordlists + ["/usr/share/wordlists/dirb/common.txt"]
        wordlist = generated if generated and os.path.exists(generated) else next(
            (w for w in fallback if os.path.exists(w)), None
        )
        if not wordlist:
            return None

        output_file = os.path.join(output_dir, f"{self.tool_name}.txt")
        args = [target.url, wordlist, "-o", output_file, "-S"]

        return ToolExecutionPlan(
            tool=self.tool_name,
            target=target.input,
            arguments=args,
            output_file=output_file,
        )
