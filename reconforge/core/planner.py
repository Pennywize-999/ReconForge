from reconforge.core.models import ReconTarget, ReconPlan
from typing import Dict, Any

class ReconPlanner:
    def __init__(self, output_directory: str = "sessions/current"):
        self.output_directory = output_directory

    def plan(self, target: ReconTarget) -> ReconPlan:
        """
        Creates a service-aware and WAF-aware execution plan based on the target.
        """
        modules = []
        metadata: Dict[str, Any] = {}

        # 1. Base Service Selection
        if target.target_type == "ip":
            modules.append("Network Analysis (Nmap)")
            modules.append("Service Discovery")
        elif target.target_type == "url":
            modules.append("Web Analysis")
            if target.scheme == "https":
                modules.append("TLS Analysis")

        # 2. WAF-Aware Constraints
        if target.mode == "WAF-Aware Low-Impact Recon":
            metadata["respect_rate_limits"] = True
            metadata["respect_retry_after"] = True
            metadata["avoid_duplicate_requests"] = True
            metadata["stop_on_repeated_blocking"] = True
            metadata["evasion_techniques"] = False
        else:
            metadata["respect_rate_limits"] = False
            metadata["respect_retry_after"] = False

        return ReconPlan(
            mode=target.mode,
            target=target,
            modules=modules,
            output_directory=self.output_directory,
            metadata=metadata
        )
