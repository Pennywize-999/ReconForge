from typing import Any, Dict

from sentinelrecon.core.models import ReconPlan, ReconTarget


class ReconPlanner:
    def __init__(self, output_directory: str = None):
        self.output_directory = output_directory

    def plan(self, target: ReconTarget) -> ReconPlan:
        modules = []
        components = []
        metadata: Dict[str, Any] = {
            "discovery_profile": target.discovery_profile.upper(),
            "components": components,
        }

        # DNS Intelligence
        modules.append("ForgeDNS")
        components.append("ForgeDNS")

        if target.target_type == "ip":
            modules.extend(["ForgeScan", "Network Analysis (Nmap)", "Service Intelligence"])
            components.append("ForgeScan")
        elif target.target_type == "url":
            modules.extend([
                "ForgeProbe", "Web Analysis",
                "ForgeTech", "Technology Identification (WhatWeb)",
                "ForgeDiscover",
            ])
            components.extend(["ForgeProbe", "ForgeTech", "ForgeDiscover"])
            if target.scheme == "https":
                modules.extend(["ForgeTLS", "TLS Analysis"])
                components.append("ForgeTLS")

        modules.extend(["SentinelCore", "VulnerabilityAssessment", "FindingsCorrelation", "Report"])
        components.extend(["SentinelCore", "VulnerabilityAssessment", "FindingsCorrelation", "Report"])

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
