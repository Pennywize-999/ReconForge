"""Adaptive service capability router."""

from __future__ import annotations

from typing import Optional, Tuple

from sentinelrecon.core.models import Host, Port
from sentinelrecon.services.classifier import ServiceCapability, ServiceClassifier, ServiceIdentity


class ServiceCapabilityRouter:
    """Routes discovered services to targeted enumeration capabilities."""

    def __init__(self, classifier: Optional[ServiceClassifier] = None):
        self.classifier = classifier or ServiceClassifier()

    def get_route_description(self, port: Port, host: Optional[Host] = None) -> str:
        ident: ServiceIdentity = self.classifier.classify(port, host)

        if ident.is_web:
            route = "HTTP Probing -> Technology Detection -> Content Discovery"
            if ident.is_tls:
                route += " -> TLS Inspection"
            return route

        if ident.is_ajp:
            return "AJP Service Intelligence (Tomcat connector)"

        if ident.is_ssh:
            return "SSH Intelligence (Banner / Auth audit)"

        if ident.is_smb:
            return "SMB Intelligence (Shares / Null session audit)"

        if ident.is_dns:
            return "DNS Intelligence (Zone / Records audit)"

        if ident.is_database:
            return f"{ident.capability.value} Service Intelligence"

        if ident.is_ftp:
            return "FTP Intelligence (Banner / Auth audit)"

        if ident.is_smtp:
            return "SMTP Intelligence (Mail relay audit)"

        if ident.is_ldap:
            return "LDAP Intelligence (Directory enumeration)"

        if ident.is_snmp:
            return "SNMP Intelligence (Community string probe)"

        return "Inventory & Version Intelligence"

    def should_skip_web_enumeration(self, port: Port, host: Optional[Host] = None) -> Tuple[bool, str]:
        ident: ServiceIdentity = self.classifier.classify(port, host)
        if ident.is_web:
            return False, ""
        if ident.is_ajp:
            return True, "AJP is not HTTP; standard HTTP directory enumeration skipped."
        return True, f"{ident.capability.value} is not an HTTP service; web directory enumeration skipped."
