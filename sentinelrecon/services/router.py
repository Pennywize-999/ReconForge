"""Adaptive service capability router."""

from __future__ import annotations

from typing import Optional

from sentinelrecon.core.models import Host, Port
from sentinelrecon.services.classifier import ServiceCapability, ServiceClassifier


class ServiceCapabilityRouter:
    """Routes discovered services to targeted enumeration capabilities."""

    def __init__(self, classifier: Optional[ServiceClassifier] = None):
        self.classifier = classifier or ServiceClassifier()

    def get_route_description(self, port: Port, host: Optional[Host] = None) -> str:
        classification = self.classifier.classify(port, host)

        if classification.is_web:
            route = "ForgeProbe -> ForgeTech -> ForgeDiscover"
            if classification.is_tls:
                route += " -> ForgeTLS"
            return route

        if classification.is_ajp:
            return "AJP Service Intelligence (Tomcat connector)"

        if classification.is_ssh:
            return "SSH Intelligence (Banner / Auth audit)"

        if classification.is_smb:
            return "SMB Intelligence (Shares / Null session audit)"

        if classification.is_dns:
            return "DNS Intelligence (Zone / Records audit)"

        if classification.is_database:
            return f"{classification.capability.value} Service Intelligence"

        return "Inventory & Version Intelligence"

    def should_skip_web_enumeration(self, port: Port, host: Optional[Host] = None) -> tuple[bool, str]:
        classification = self.classifier.classify(port, host)
        if classification.is_web:
            return False, ""
        if classification.is_ajp:
            return True, "AJP is not HTTP; standard HTTP directory enumeration skipped."
        return True, f"{classification.capability.value} is not an HTTP service; web directory enumeration skipped."
