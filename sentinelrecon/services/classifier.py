"""Service classification and protocol capability identification."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from sentinelrecon.core.models import Host, Port, Service


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
class ServiceClassification:
    capability: ServiceCapability
    is_web: bool = False
    is_tls: bool = False
    is_ajp: bool = False
    is_ssh: bool = False
    is_smb: bool = False
    is_dns: bool = False
    is_database: bool = False
    certainty: ServiceCertainty = ServiceCertainty.UNKNOWN
    description: str = ""


class ServiceClassifier:
    """Classifies network services based on banners, products, service names, and protocol probes."""

    WEB_PORTS = {80, 8080, 8000, 8008, 8081, 8088, 8888, 3000, 5000, 9000}
    TLS_PORTS = {443, 8443, 9443, 4443}

    def classify(self, port: Port, host: Optional[Host] = None) -> ServiceClassification:
        service_name = (port.service.name if port.service else "").lower().strip()
        product = (port.service.product if port.service else "").lower().strip()
        extra_info = (port.service.extra_info if port.service and hasattr(port.service, "extra_info") else "").lower().strip()

        combined = f"{service_name} {product} {extra_info}"

        # 1. AJP Protocol
        if "ajp" in service_name or "ajp13" in service_name or "apache jserv" in product or "ajp" in product or port.number == 8009:
            return ServiceClassification(
                capability=ServiceCapability.AJP,
                is_ajp=True,
                certainty=ServiceCertainty.IDENTIFIED,
                description="Apache JServ Protocol (AJP13)",
            )

        # 2. Web Services (HTTP / HTTPS)
        is_tls = port.number in self.TLS_PORTS or "https" in service_name or "ssl" in service_name or "ssl" in combined
        is_http = (
            "http" in service_name
            or "http" in product
            or "www" in service_name
            or "nginx" in product
            or "apache" in product
            or "lighttpd" in product
            or "caddy" in product
            or "tomcat" in product
            or port.number in self.WEB_PORTS
            or is_tls
        )
        if is_http:
            return ServiceClassification(
                capability=ServiceCapability.WEB,
                is_web=True,
                is_tls=is_tls,
                certainty=ServiceCertainty.IDENTIFIED,
                description="HTTPS Web Service" if is_tls else "HTTP Web Service",
            )

        # 3. SSH Service
        if "ssh" in service_name or "openssh" in product or port.number == 22:
            return ServiceClassification(
                capability=ServiceCapability.SSH,
                is_ssh=True,
                certainty=ServiceCertainty.IDENTIFIED,
                description="SSH Secure Shell",
            )

        # 4. SMB / NetBIOS
        if "smb" in service_name or "microsoft-ds" in service_name or "netbios" in service_name or "samba" in product or port.number in {139, 445}:
            return ServiceClassification(
                capability=ServiceCapability.SMB,
                is_smb=True,
                certainty=ServiceCertainty.IDENTIFIED,
                description="SMB / Windows File Sharing",
            )

        # 5. DNS Service
        if "domain" in service_name or "dns" in service_name or "bind" in product or port.number == 53:
            return ServiceClassification(
                capability=ServiceCapability.DNS,
                is_dns=True,
                certainty=ServiceCertainty.IDENTIFIED,
                description="Domain Name System (DNS)",
            )

        # 6. Database Services
        if "mysql" in service_name or "mariadb" in product or port.number == 3306:
            return ServiceClassification(
                capability=ServiceCapability.MYSQL,
                is_database=True,
                certainty=ServiceCertainty.IDENTIFIED,
                description="MySQL / MariaDB Database",
            )
        if "postgresql" in service_name or "postgres" in service_name or port.number == 5432:
            return ServiceClassification(
                capability=ServiceCapability.POSTGRESQL,
                is_database=True,
                certainty=ServiceCertainty.IDENTIFIED,
                description="PostgreSQL Database",
            )
        if "redis" in service_name or port.number == 6379:
            return ServiceClassification(
                capability=ServiceCapability.REDIS,
                is_database=True,
                certainty=ServiceCertainty.IDENTIFIED,
                description="Redis In-Memory Datastore",
            )
        if "mongodb" in service_name or port.number == 27017:
            return ServiceClassification(
                capability=ServiceCapability.MONGODB,
                is_database=True,
                certainty=ServiceCertainty.IDENTIFIED,
                description="MongoDB NoSQL Database",
            )

        # 7. FTP / SMTP / SNMP / LDAP
        if "ftp" in service_name or port.number == 21:
            return ServiceClassification(capability=ServiceCapability.FTP, certainty=ServiceCertainty.IDENTIFIED, description="File Transfer Protocol (FTP)")
        if "smtp" in service_name or port.number in {25, 465, 587}:
            return ServiceClassification(capability=ServiceCapability.SMTP, certainty=ServiceCertainty.IDENTIFIED, description="Simple Mail Transfer Protocol (SMTP)")
        if "snmp" in service_name or port.number in {161, 162}:
            return ServiceClassification(capability=ServiceCapability.SNMP, certainty=ServiceCertainty.IDENTIFIED, description="Simple Network Management Protocol (SNMP)")
        if "ldap" in service_name or port.number in {389, 636}:
            return ServiceClassification(capability=ServiceCapability.LDAP, certainty=ServiceCertainty.IDENTIFIED, description="Lightweight Directory Access Protocol (LDAP)")

        return ServiceClassification(
            capability=ServiceCapability.GENERIC,
            certainty=ServiceCertainty.UNKNOWN if not service_name else ServiceCertainty.POSSIBLE,
            description="Generic / Inventory Service",
        )
