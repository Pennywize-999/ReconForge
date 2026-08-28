"""Service classification, protocol capability identification, and service identity modeling."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from sentinelrecon.core.models import Confidence, Host, Port, Service


class ServiceCapability(Enum):
    WEB = "WEB"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    AJP = "AJP"
    SSH = "SSH"
    SMB = "SMB"
    DNS = "DNS"
    FTP = "FTP"
    SMTP = "SMTP"
    SNMP = "SNMP"
    LDAP = "LDAP"
    MYSQL = "MYSQL"
    POSTGRESQL = "POSTGRESQL"
    REDIS = "REDIS"
    MONGODB = "MONGODB"
    GENERIC = "GENERIC"


class ServiceCertainty(Enum):
    IDENTIFIED = "IDENTIFIED"
    POSSIBLE = "POSSIBLE"
    UNKNOWN = "UNKNOWN"


@dataclass
class ServiceIdentity:
    """Explicit service identity containing detected protocol, product, capability, and evidence."""

    port: int
    protocol: str = "tcp"
    detected_service: str = "unknown"
    product: str = ""
    version: str = ""
    capability: ServiceCapability = ServiceCapability.GENERIC
    confidence: Confidence = Confidence.UNKNOWN
    evidence_source: str = ""
    is_web: bool = False
    is_tls: bool = False
    is_ajp: bool = False
    is_ssh: bool = False
    is_smb: bool = False
    is_dns: bool = False
    is_database: bool = False
    is_ftp: bool = False
    is_smtp: bool = False
    is_ldap: bool = False
    is_snmp: bool = False
    certainty: ServiceCertainty = ServiceCertainty.UNKNOWN
    description: str = ""
    contradiction: Optional[str] = None


# Backward-compatible alias for existing consumers
ServiceClassification = ServiceIdentity


class ServiceClassifier:
    """Classifies network services based on evidence priority:
    1. Service detection / service name
    2. Product and version banners
    3. Protocol / extra-info evidence
    4. Active protocol verification
    5. Port number (weak fallback hint only).
    """

    WEB_DEFAULT_PORTS = {80, 8080, 8000, 8008, 8081, 8088, 8888, 3000, 5000, 9000}
    TLS_DEFAULT_PORTS = {443, 8443, 9443, 4443}
    SSH_DEFAULT_PORTS = {22, 2222}

    def classify(self, port: Port, host: Optional[Host] = None) -> ServiceIdentity:
        service_name = (port.service.name if port.service else "").lower().strip()
        product = (port.service.product if port.service else "").strip()
        product_lower = product.lower()
        version = (port.service.version if port.service else "").strip()
        extra_info = (
            getattr(port.service, "extra_info", "") if port.service else ""
        ).strip()
        extra_lower = extra_info.lower()

        combined = f"{service_name} {product_lower} {extra_lower}"

        # Initialize base identity
        ident = ServiceIdentity(
            port=port.number,
            protocol=port.protocol,
            detected_service=service_name or "unknown",
            product=product,
            version=version,
        )

        # Check if host has verified web endpoints on this port
        has_verified_web = False
        if host and host.web_endpoints:
            for ep in host.web_endpoints:
                try:
                    from urllib.parse import urlparse

                    parsed = urlparse(ep.url)
                    ep_port = parsed.port or (443 if parsed.scheme == "https" else 80)
                    if ep_port == port.number:
                        has_verified_web = True
                        break
                except Exception:
                    pass

        # -------------------------------------------------------------
        # PRIORITY 1 & 2: Explicit Service and Product Detection
        # -------------------------------------------------------------

        # A. AJP Protocol (e.g. port 8009 or ajp13 service)
        if "ajp" in service_name or "apache jserv" in product_lower or "ajp" in product_lower:
            ident.capability = ServiceCapability.AJP
            ident.is_ajp = True
            ident.confidence = Confidence.HIGH
            ident.certainty = ServiceCertainty.IDENTIFIED
            ident.evidence_source = f"Service detection ({product or 'AJP13 connector'})"
            ident.description = "Apache JServ Protocol (AJP13)"
            if port.number != 8009:
                ident.contradiction = f"AJP service running on non-standard port {port.number}"
            return ident

        # B. SSH Service (e.g. 22/tcp or 80/tcp running OpenSSH)
        if "ssh" in service_name or "openssh" in product_lower or "dropbear" in product_lower:
            ident.capability = ServiceCapability.SSH
            ident.is_ssh = True
            ident.confidence = Confidence.HIGH
            ident.certainty = ServiceCertainty.IDENTIFIED
            ident.evidence_source = f"SSH banner / service detection ({product or 'SSH'})"
            ident.description = "SSH Secure Shell"
            if port.number in self.WEB_DEFAULT_PORTS:
                ident.contradiction = f"SSH service running on port {port.number} (overrides HTTP default)"
            return ident

        # C. SMB / NetBIOS
        if (
            "smb" in service_name
            or "microsoft-ds" in service_name
            or "netbios" in service_name
            or "samba" in product_lower
        ):
            ident.capability = ServiceCapability.SMB
            ident.is_smb = True
            ident.confidence = Confidence.HIGH
            ident.certainty = ServiceCertainty.IDENTIFIED
            ident.evidence_source = f"SMB service detection ({product or service_name})"
            ident.description = "SMB / Windows File Sharing"
            return ident

        # D. DNS Service
        if "domain" in service_name or "dns" in service_name or "bind" in product_lower:
            ident.capability = ServiceCapability.DNS
            ident.is_dns = True
            ident.confidence = Confidence.HIGH
            ident.certainty = ServiceCertainty.IDENTIFIED
            ident.evidence_source = f"DNS service detection ({product or service_name})"
            ident.description = "Domain Name System (DNS)"
            return ident

        # E. Database Services
        if "mysql" in service_name or "mariadb" in product_lower:
            ident.capability = ServiceCapability.MYSQL
            ident.is_database = True
            ident.confidence = Confidence.HIGH
            ident.certainty = ServiceCertainty.IDENTIFIED
            ident.evidence_source = f"Database service detection ({product or 'MySQL'})"
            ident.description = "MySQL / MariaDB Database"
            return ident

        if "postgresql" in service_name or "postgres" in service_name:
            ident.capability = ServiceCapability.POSTGRESQL
            ident.is_database = True
            ident.confidence = Confidence.HIGH
            ident.certainty = ServiceCertainty.IDENTIFIED
            ident.evidence_source = f"Database service detection ({product or 'PostgreSQL'})"
            ident.description = "PostgreSQL Database"
            return ident

        if "redis" in service_name:
            ident.capability = ServiceCapability.REDIS
            ident.is_database = True
            ident.confidence = Confidence.HIGH
            ident.certainty = ServiceCertainty.IDENTIFIED
            ident.evidence_source = "Redis service detection"
            ident.description = "Redis In-Memory Datastore"
            return ident

        if "mongodb" in service_name:
            ident.capability = ServiceCapability.MONGODB
            ident.is_database = True
            ident.confidence = Confidence.HIGH
            ident.certainty = ServiceCertainty.IDENTIFIED
            ident.evidence_source = "MongoDB service detection"
            ident.description = "MongoDB NoSQL Database"
            return ident

        # F. FTP / SMTP / SNMP / LDAP
        if "ftp" in service_name or "vsftpd" in product_lower or "proftpd" in product_lower:
            ident.capability = ServiceCapability.FTP
            ident.is_ftp = True
            ident.confidence = Confidence.HIGH
            ident.certainty = ServiceCertainty.IDENTIFIED
            ident.evidence_source = f"FTP service detection ({product or service_name})"
            ident.description = "File Transfer Protocol (FTP)"
            return ident

        if "smtp" in service_name or "postfix" in product_lower or "exim" in product_lower:
            ident.capability = ServiceCapability.SMTP
            ident.is_smtp = True
            ident.confidence = Confidence.HIGH
            ident.certainty = ServiceCertainty.IDENTIFIED
            ident.evidence_source = f"SMTP service detection ({product or service_name})"
            ident.description = "Simple Mail Transfer Protocol (SMTP)"
            return ident

        if "snmp" in service_name:
            ident.capability = ServiceCapability.SNMP
            ident.is_snmp = True
            ident.confidence = Confidence.HIGH
            ident.certainty = ServiceCertainty.IDENTIFIED
            ident.evidence_source = "SNMP service detection"
            ident.description = "Simple Network Management Protocol (SNMP)"
            return ident

        if "ldap" in service_name or "openldap" in product_lower:
            ident.capability = ServiceCapability.LDAP
            ident.is_ldap = True
            ident.confidence = Confidence.HIGH
            ident.certainty = ServiceCertainty.IDENTIFIED
            ident.evidence_source = f"LDAP service detection ({product or service_name})"
            ident.description = "Lightweight Directory Access Protocol (LDAP)"
            return ident

        # G. HTTP / HTTPS Web Services (explicit service or web server product)
        is_tls_service = (
            "https" in service_name
            or "ssl" in service_name
            or "ssl/http" in service_name
            or "https-alt" in service_name
        )
        is_http_product = any(
            w in product_lower
            for w in [
                "apache httpd",
                "apache http server",
                "nginx",
                "lighttpd",
                "caddy",
                "tomcat",
                "jetty",
                "microsoft iis",
                "gunicorn",
                "uvicorn",
                "werkzeug",
                "express",
            ]
        )
        is_http_service = "http" in service_name or "www" in service_name or is_http_product

        if is_http_service or is_tls_service or has_verified_web:
            is_tls = is_tls_service or (port.number in self.TLS_DEFAULT_PORTS and not service_name.startswith("http"))
            ident.capability = ServiceCapability.WEB
            ident.is_web = True
            ident.is_tls = is_tls
            ident.confidence = Confidence.HIGH
            ident.certainty = ServiceCertainty.IDENTIFIED
            evidence_desc = product or (service_name if service_name else "HTTP response")
            ident.evidence_source = f"Service detection ({evidence_desc})"
            ident.description = "HTTPS Web Service" if is_tls else "HTTP Web Service"
            if port.number in self.SSH_DEFAULT_PORTS:
                ident.contradiction = f"HTTP web service running on port {port.number} (overrides SSH default)"
            return ident

        # -------------------------------------------------------------
        # PRIORITY 5: Port Fallback Hint (Only when service is unknown)
        # -------------------------------------------------------------
        if not service_name or service_name in {"unknown", "tcpwrapped", "unassigned"}:
            if port.number == 8009:
                ident.capability = ServiceCapability.AJP
                ident.is_ajp = True
                ident.confidence = Confidence.MEDIUM
                ident.certainty = ServiceCertainty.POSSIBLE
                ident.evidence_source = "Port 8009 heuristic fallback"
                ident.description = "AJP Service (Heuristic)"
                return ident

            if port.number in self.SSH_DEFAULT_PORTS:
                ident.capability = ServiceCapability.SSH
                ident.is_ssh = True
                ident.confidence = Confidence.LOW
                ident.certainty = ServiceCertainty.POSSIBLE
                ident.evidence_source = f"Port {port.number} fallback hint"
                ident.description = "SSH Service (Heuristic)"
                return ident

            if port.number in self.TLS_DEFAULT_PORTS:
                ident.capability = ServiceCapability.HTTPS
                ident.is_web = True
                ident.is_tls = True
                ident.confidence = Confidence.LOW
                ident.certainty = ServiceCertainty.POSSIBLE
                ident.evidence_source = f"Port {port.number} fallback hint"
                ident.description = "HTTPS Web Service (Heuristic)"
                return ident

            if port.number in self.WEB_DEFAULT_PORTS:
                ident.capability = ServiceCapability.HTTP
                ident.is_web = True
                ident.confidence = Confidence.LOW
                ident.certainty = ServiceCertainty.POSSIBLE
                ident.evidence_source = f"Port {port.number} fallback hint"
                ident.description = "HTTP Web Service (Heuristic)"
                return ident

            if port.number in {139, 445}:
                ident.capability = ServiceCapability.SMB
                ident.is_smb = True
                ident.confidence = Confidence.LOW
                ident.certainty = ServiceCertainty.POSSIBLE
                ident.evidence_source = f"Port {port.number} fallback hint"
                ident.description = "SMB Service (Heuristic)"
                return ident

            if port.number == 53:
                ident.capability = ServiceCapability.DNS
                ident.is_dns = True
                ident.confidence = Confidence.LOW
                ident.certainty = ServiceCertainty.POSSIBLE
                ident.evidence_source = "Port 53 fallback hint"
                ident.description = "DNS Service (Heuristic)"
                return ident

        # Generic / Unknown
        ident.capability = ServiceCapability.GENERIC
        ident.confidence = Confidence.LOW if service_name else Confidence.UNKNOWN
        ident.certainty = ServiceCertainty.POSSIBLE if service_name else ServiceCertainty.UNKNOWN
        ident.evidence_source = f"Port scan ({service_name or 'unclassified'})"
        ident.description = f"Generic / {service_name.capitalize()} Service" if service_name else "Generic Service"
        return ident
