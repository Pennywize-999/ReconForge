import os
from typing import Any

from reconforge.core.models import ReconTarget
from reconforge.tools.models import ToolExecutionPlan
from reconforge.tools.adapters.base import ToolAdapter

class GobusterAdapter(ToolAdapter):
    @property
    def tool_name(self) -> str:
        return "gobuster"

    @property
    def parser_name(self) -> str:
        return "GobusterParser"

    def supports_target(self, target: ReconTarget) -> bool:
        return target.scheme in ["http", "https"]

    def build_plan(self, target: ReconTarget, output_dir: str, **kwargs: Any) -> Any:
        from reconforge.core.config import load_config
        config = load_config()
        depth = getattr(target, "depth", "Common")
        mode = getattr(target, "mode", "Standard Recon")

        wordlists = config.default_wordlists + ["/usr/share/wordlists/dirb/common.txt"]
        wordlist = next((w for w in wordlists if os.path.exists(w)), None)

        if not wordlist:
            return None

        output_file = os.path.join(output_dir, f"{self.tool_name}.txt")

        threads = config.gobuster_threads
        if mode == "WAF-Aware Low-Impact Recon":
            threads = min(threads, 5)

        args = ["dir", "-u", target.url, "-w", wordlist, "-o", output_file, "-t", str(threads)]

        if depth == "Medium":
            args.extend(["-x", "php,html,txt"])
        elif depth == "Deep":
            args.extend(["-x", "php,html,txt,json,xml,bak,zip"])

        return ToolExecutionPlan(
            tool=self.tool_name,
            target=target.input,
            arguments=args,
            output_file=output_file
        )

