from reconforge.core.models import ReconTarget, ReconPlan
from typing import Dict, Any


class ReconPlanner:
    def __init__(self, output_directory: str = "sessions/current"):
        self.output_directory = output_directory

    def plan(self, target: ReconTarget) -> ReconPlan:
        modules = []
        metadata: Dict[str, Any] = {
            "discovery_profile": target.discovery_profile.upper(),
            "components": [],
        }

        if target.target_type == "ip":
            modules.extend(["ForgeScan", "Service Intelligence"])
            metadata["components"].append("ForgeScan")
        elif target.target_type == "url":
            modules.extend(["ForgeProbe", "ForgeTech", "ForgeDiscover"])
            metadata["components"].extend(["ForgeProbe", "ForgeTech", "ForgeDiscover"])
            if target.scheme == "https":
                modules.append("ForgeTLS")
                metadata["components"].append("ForgeTLS")

        modules.extend(["ForgeCore", "ForgeIntel", "ForgeReport"])
        metadata["components"].extend(["ForgeCore", "ForgeIntel", "ForgeReport"])

        if target.mode == "WAF-Aware Low-Impact Recon":
            metadata.update({
                "respect_rate_limits": True,
                "respect_retry_after": True,
                "avoid_duplicate_requests": True,
                "stop_on_repeated_blocking": True,
                "evasion_techniques": False,
            })
        else:
            metadata.update({
                "respect_rate_limits": False,
                "respect_retry_after": False,
                "avoid_duplicate_requests": True,
                "evasion_techniques": False,
            })

        return ReconPlan(
            mode=target.mode,
            target=target,
            modules=modules,
            output_directory=self.output_directory,
            metadata=metadata,
        )
