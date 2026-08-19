import os
from typing import List, Tuple

from reconforge.core.models import Host, Finding, Evidence, Confidence, FindingType
from reconforge.parsers.base import BaseParser

class GenericTextParser(BaseParser):
    @classmethod
    def can_parse(cls, file_path: str) -> bool:
        return file_path.endswith('.txt') or file_path.endswith('.log')

    @classmethod
    def parse(cls, file_path: str) -> Tuple[List[Host], List[Finding], List[str]]:
        hosts: List[Host] = []
        findings: List[Finding] = []
        errors: List[str] = []

        # This is a fallback parser, it shouldn't produce empty findings.
        # Only parse if there's no other specialized parser, which is handled by analyzer's order.
        content = cls.read_file_safe(file_path)
        if not content:
            return hosts, findings, ["Failed to read generic file"]

        filename = os.path.basename(file_path)

        # We just create a generic finding
        finding = Finding(
            title=f"Unstructured Output: {filename}",
            finding_type=FindingType.INFORMATION,
            severity="INFO",
            confidence=Confidence.LOW,
            description="This file was parsed generically because no specific parser matched it.",
            source_file=filename,
            source_type="Generic",
            evidence=[Evidence(source_file=filename, source_type="Generic", content=content[:500] + "...")]
        )

        # We attach it to a finding list (not bound to a host initially, but we can bind to an 'unknown' host)
        host = Host(ip="unknown", status="up")
        host.findings.append(finding)
        hosts.append(host)

        return hosts, findings, errors
