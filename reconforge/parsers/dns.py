import os
import re
from typing import List, Tuple

from reconforge.core.models import Host, Finding, Evidence, Confidence, FindingType
from reconforge.parsers.base import BaseParser

class DNSParser(BaseParser):
    @classmethod
    def can_parse(cls, file_path: str) -> bool:
        if not file_path.endswith('.txt'):
            return False
        content = cls.read_file_safe(file_path)[:500]
        return "has address" in content or "name server" in content or "AXFR" in content

    @classmethod
    def parse(cls, file_path: str) -> Tuple[List[Host], List[Finding], List[str]]:
        hosts: List[Host] = []
        findings: List[Finding] = []
        errors: List[str] = []

        content = cls.read_file_safe(file_path)
        if not content:
            return hosts, findings, ["Failed to read DNS file"]

        filename = os.path.basename(file_path)

        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue

            # e.g., web01.local has address 10.10.10.25
            match = re.match(r'^([a-zA-Z0-9\.\-]+)\s+has address\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$', line)
            if match:
                hostname = match.group(1)
                ip = match.group(2)

                host = next((h for h in hosts if h.ip == ip), None)
                if not host:
                    host = Host(ip=ip, status="up")
                    hosts.append(host)

                if hostname not in host.hostnames:
                    host.hostnames.append(hostname)

            if "Transfer failed" in line or "AXFR record query failed" in line:
                continue

            if "AXFR" in line and "success" in line.lower():
                finding = Finding(
                    title="DNS Zone Transfer (AXFR) Successful",
                    finding_type=FindingType.VULNERABILITY,
                    severity="HIGH",
                    confidence=Confidence.HIGH,
                    description="The DNS server allows anonymous zone transfers, exposing internal records.",
                    source_file=filename,
                    source_type="DNS",
                    evidence=[Evidence(source_file=filename, source_type="DNS", content=line)]
                )
                findings.append(finding)

        return hosts, findings, errors
