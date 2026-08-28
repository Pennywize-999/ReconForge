import os
import re
from typing import List, Tuple

from sentinelrecon.core.models import Confidence, Evidence, Finding, FindingType, Host
from sentinelrecon.parsers.base import BaseParser


class DNSParser(BaseParser):
    @classmethod
    def can_parse(cls, file_path: str) -> bool:
        if not file_path.endswith(".txt"):
            return False
        content = cls.read_file_safe(file_path)[:1000].lower()
        return (
            "has address" in content
            or "name server" in content
            or "domain name pointer" in content
            or "nameserver" in content
            or "axfr" in content
        )

    @classmethod
    def parse(cls, file_path: str) -> Tuple[List[Host], List[Finding], List[str]]:
        hosts: List[Host] = []
        findings: List[Finding] = []
        errors: List[str] = []
        content = cls.read_file_safe(file_path)
        if not content:
            return hosts, findings, ["Failed to read DNS file"]

        filename = os.path.basename(file_path)
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            match = re.match(r"^([a-zA-Z0-9._-]+)\s+has address\s+(\d{1,3}(?:\.\d{1,3}){3})$", line)
            if match:
                hostname, ip = match.groups()
                host = next((h for h in hosts if h.ip == ip), None)
                if not host:
                    host = Host(ip=ip, status="up")
                    hosts.append(host)
                if hostname not in host.hostnames:
                    host.hostnames.append(hostname)
                continue

            ptr = re.search(r"^([^\s]+)\s+domain name pointer\s+([^\s.]+(?:\.[^\s.]+)*)\.?$", line, re.I)
            if ptr:
                query, hostname = ptr.groups()
                ip_match = re.match(r"^(\d+)\.(\d+)\.(\d+)\.(\d+)\.in-addr\.arpa$", query, re.I)
                ip = ".".join(reversed(ip_match.groups())) if ip_match else "unknown"
                host = next((h for h in hosts if h.ip == ip), None)
                if not host:
                    host = Host(ip=ip, status="up")
                    hosts.append(host)
                if hostname not in host.hostnames:
                    host.hostnames.append(hostname)
                continue

            if "AXFR" in line and "success" in line.lower():
                findings.append(
                    Finding(
                        title="DNS Zone Transfer (AXFR) Successful",
                        finding_type=FindingType.VULNERABILITY,
                        severity="HIGH",
                        confidence=Confidence.HIGH,
                        description="The DNS server allows anonymous zone transfers, exposing DNS records.",
                        source_file=filename,
                        source_type="DNS Intelligence",
                        evidence=[Evidence(source_file=filename, source_type="DNS Intelligence", content=line)],
                    )
                )

        return hosts, findings, errors
