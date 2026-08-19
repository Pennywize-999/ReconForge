import os
import re
from typing import List, Tuple

from reconforge.core.models import Host, Finding, Evidence, Confidence, FindingType
from reconforge.parsers.base import BaseParser

class TLSParser(BaseParser):
    @classmethod
    def can_parse(cls, file_path: str) -> bool:
        if not file_path.endswith('.txt'):
            return False
        content = cls.read_file_safe(file_path)[:500]
        return "CONNECTED(0000" in content or "Server certificate" in content

    @classmethod
    def parse(cls, file_path: str) -> Tuple[List[Host], List[Finding], List[str]]:
        hosts: List[Host] = []
        findings: List[Finding] = []
        errors: List[str] = []

        content = cls.read_file_safe(file_path)
        if not content:
            return hosts, findings, ["Failed to read TLS file"]

        filename = os.path.basename(file_path)
        ip_guess = "unknown"
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', filename)
        if ip_match:
            ip_guess = ip_match.group(1)

        host = Host(ip=ip_guess, status="up")

        # Simple extraction of subject/issuer
        subject_match = re.search(r'subject=.*?CN\s*=\s*([^,\n]+)', content)
        if subject_match:
            cn = subject_match.group(1).strip()
            if cn and cn not in host.hostnames:
                host.hostnames.append(cn)

            finding = Finding(
                title="TLS Certificate Subject Found",
                finding_type=FindingType.INFORMATION,
                severity="INFO",
                confidence=Confidence.HIGH,
                description=f"Found CN: {cn}",
                source_file=filename,
                source_type="TLS",
                evidence=[Evidence(source_file=filename, source_type="TLS", content=subject_match.group(0))]
            )
            host.findings.append(finding)

        # Check for expired/weak certs
        if "Verify return code: 10 (certificate has expired)" in content:
            finding = Finding(
                title="Expired TLS Certificate",
                finding_type=FindingType.POTENTIAL_ISSUE,
                severity="MEDIUM",
                confidence=Confidence.HIGH,
                description="The TLS certificate has expired.",
                source_file=filename,
                source_type="TLS",
                evidence=[Evidence(source_file=filename, source_type="TLS", content="Verify return code: 10")]
            )
            host.findings.append(finding)

        if host.findings or host.hostnames:
            hosts.append(host)

        return hosts, findings, errors
