import os
from typing import Optional
from sentinelrecon.core.config import load_config
from sentinelrecon.core.discovery import get_discovery_profile
from sentinelrecon.core.models import ReconTarget
from sentinelrecon.tools.adapters.base import BaseToolAdapter
from sentinelrecon.tools.models import ToolExecutionPlan


class DirbAdapter(BaseToolAdapter):
    def __init__(self):
        super().__init__("dirb")

    def supports_target(self, target: ReconTarget) -> bool:
        return target.target_type == "url"

    def _build_combined_wordlist(self, output_dir: str, profile_name: str) -> str:
        config = load_config()
        profile = get_discovery_profile(profile_name)

        combined_words = []
        default_wl = os.path.join(config.wordlist_dir, profile.default_wordlist)
        if os.path.exists(default_wl):
            with open(default_wl, "r", encoding="utf-8", errors="ignore") as f:
                combined_words.extend([line.strip() for line in f if line.strip() and not line.startswith("#")])

        for cat in profile.category_wordlists:
            cat_wl = os.path.join(config.wordlist_dir, cat)
            if os.path.exists(cat_wl):
                with open(cat_wl, "r", encoding="utf-8", errors="ignore") as f:
                    combined_words.extend([line.strip() for line in f if line.strip() and not line.startswith("#")])

        seen = set()
        unique_words = []
        for w in combined_words:
            if w not in seen:
                seen.add(w)
                unique_words.append(w)

        merged_file = os.path.join(output_dir, f"sentinelrecon_{profile_name.lower()}_wordlist.txt")
        with open(merged_file, "w", encoding="utf-8") as f:
            for w in unique_words:
                f.write(f"{w}\n")

        return merged_file

    def build_plan(self, target: ReconTarget, output_directory: str, **kwargs) -> Optional[ToolExecutionPlan]:
        if not self.supports_target(target):
            return None

        output_file = os.path.join(output_directory, "dirb.txt")
        profile_name = target.discovery_profile or "COMMON"
        wordlist_path = self._build_combined_wordlist(output_directory, profile_name)

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
