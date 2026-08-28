import os
import re
from typing import List, Tuple

from sentinelrecon.core.models import Confidence, Evidence, Finding, FindingType, Host
from sentinelrecon.parsers.base import BaseParser


class SMBParser(BaseParser):
    @classmethod
    def can_parse(cls, file_path: str) -> bool:
        if not file_path.endswith(".txt"):
            return False
        content = cls.read_file_safe(file_path)[:500]
        return "smbclient" in content.lower() or "enum4linux" in content.lower() or "Sharename" in content

    @classmethod
    def parse(cls, file_path: str) -> Tuple[List[Host], List[Finding], List[str]]:
        hosts: List[Host] = []
        findings: List[Finding] = []
        errors: List[str] = []

        content = cls.read_file_safe(file_path)
        if not content:
            return hosts, findings, ["Failed to read SMB file"]

        filename = os.path.basename(file_path)
        ip_guess = "unknown"
        ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", filename)
        if ip_match:
            ip_guess = ip_match.group(1)

        host = Host(ip=ip_guess, status="up")

        if "Sharename" in content and "Type" in content:
            shares = []
            capture = False
            for line in content.splitlines():
                if "Sharename" in line:
                    capture = True
                    continue
                if capture and line.strip() == "":
                    break
                if capture and not line.startswith("\t---------"):
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        shares.append(parts[0])

            if shares:
                finding = Finding(
                    title="SMB Shares Enumerated",
                    finding_type=FindingType.INFORMATION,
                    severity="INFO",
                    confidence=Confidence.HIGH,
                    description=f"The following shares were found: {', '.join(shares)}",
                    source_file=filename,
                    source_type="SMB Intelligence",
                    evidence=[Evidence(source_file=filename, source_type="SMB Intelligence", content=f"Shares: {shares}")],
                )
                host.findings.append(finding)

        if "Anonymous login successful" in content or "NT_STATUS_OK" in content and "Anonymous" in content:
            finding = Finding(
                title="SMB Null Session Allowed",
                finding_type=FindingType.POTENTIAL_ISSUE,
                severity="MEDIUM",
                confidence=Confidence.HIGH,
                description="The SMB server allows anonymous null sessions.",
                source_file=filename,
                source_type="SMB Intelligence",
                evidence=[Evidence(source_file=filename, source_type="SMB Intelligence", content="Anonymous login successful")],
            )
            host.findings.append(finding)

        if host.findings:
            hosts.append(host)

        return hosts, findings, errors
