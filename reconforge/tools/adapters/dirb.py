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
        # Add common Kali wordlist to defaults
        wordlists = config.default_wordlists + ["/usr/share/wordlists/dirb/common.txt"]
        wordlist = next((w for w in wordlists if os.path.exists(w)), None)

        if not wordlist:
            return None # Will be skipped

        output_file = os.path.join(output_dir, f"{self.tool_name}.txt")
        args = [target.url, wordlist, "-o", output_file, "-S"]

        return ToolExecutionPlan(
            tool=self.tool_name,
            target=target.input,
            arguments=args,
            output_file=output_file
        )
