"""Reconnaissance execution planner constructing capabilities-based execution plans."""

from typing import Any, Dict

from sentinelrecon.core.models import ReconPlan, ReconTarget


class ReconPlanner:
    def __init__(self, output_directory: str = None):
        self.output_directory = output_directory

    def plan(self, target: ReconTarget) -> ReconPlan:
        modules = []
        components = []
        profile_name = getattr(target, "discovery_profile", "AUTONOMOUS") or "AUTONOMOUS"
        metadata: Dict[str, Any] = {
            "discovery_profile": profile_name.upper(),
            "components": components,
        }

        # 1. Network & DNS Discovery
        modules.append("Network Discovery")
        components.append("Network Discovery")

        if target.target_type == "ip":
            modules.extend(["Service Analysis", "Technology Detection", "Adaptive Discovery"])
            components.extend(["Service Analysis", "Technology Detection", "Adaptive Discovery"])
        elif target.target_type == "url":
            modules.extend(["Service Analysis", "Web Analysis", "Technology Detection", "Adaptive Discovery"])
            components.extend(["Service Analysis", "Web Analysis", "Technology Detection", "Adaptive Discovery"])
            if target.scheme == "https":
                modules.append("TLS Analysis")
                components.append("TLS Analysis")

        # 2. Vulnerability Intelligence, Correlation & Reporting
        modules.extend(["Vulnerability Assessment", "Findings Correlation", "Report Generation"])
        components.extend(["Vulnerability Assessment", "Findings Correlation", "Report Generation"])

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
