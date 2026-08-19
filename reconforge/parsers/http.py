import os
import re
from typing import List, Tuple

from reconforge.core.models import Host, Finding, Evidence, Technology, Confidence, FindingType
from reconforge.parsers.base import BaseParser

class HTTPParser(BaseParser):
    @classmethod
    def can_parse(cls, file_path: str) -> bool:
        if not file_path.endswith('.txt'):
            return False
        content = cls.read_file_safe(file_path)[:500]
        return "HTTP/1." in content and ("Server:" in content or "Content-Type:" in content)

    @classmethod
    def parse(cls, file_path: str) -> Tuple[List[Host], List[Finding], List[str]]:
        hosts: List[Host] = []
        findings: List[Finding] = []
        errors: List[str] = []

        content = cls.read_file_safe(file_path)
        if not content:
            return hosts, findings, ["Failed to read HTTP headers file"]

        # We need a target to map this to, typically it's the filename if it's named like 10.10.10.25_headers.txt
        # If not, we just create an unknown host and let the analyzer merge it if possible.
        filename = os.path.basename(file_path)
        ip_guess = "unknown"
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', filename)
        if ip_match:
            ip_guess = ip_match.group(1)

        host = Host(ip=ip_guess, status="up")

        server_match = re.search(r'(?i)^Server:\s*(.+)$', content, re.MULTILINE)
        if server_match:
            server_str = server_match.group(1).strip()

            # Simple parsing: Apache/2.4.41 (Ubuntu)
            parts = server_str.split()
            name = parts[0]
            version = None
            if "/" in name:
                name, version = name.split("/", 1)

            tech = Technology(
                name=name,
                version=version,
                sources=[filename],
                detected_values=[server_str],
                confidence=Confidence.HIGH
            )

            # Since we don't have a port, we'll just add it as a general technology finding for the host
            # Analyzer will need to handle this or we attach it to a generic WebEndpoint

            finding = Finding(
                title="HTTP Server Header Disclosed",
                finding_type=FindingType.INFORMATION,
                severity="INFO",
                confidence=Confidence.HIGH,
                description=f"The server identifies itself as: {server_str}",
                source_file=filename,
                source_type="HTTPParser",
                evidence=[Evidence(source_file=filename, source_type="HTTPParser", content=content)]
            )
            host.findings.append(finding)

        if host.findings:
            hosts.append(host)

        return hosts, findings, errors
