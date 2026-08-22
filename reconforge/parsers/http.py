import os
import re
from urllib.parse import urlparse
from typing import List, Tuple

from reconforge.core.models import Host, Finding, WebEndpoint, Technology, Confidence, FindingType
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

        filename = os.path.basename(file_path)
        ip_guess = "unknown"
        ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', filename)
        if ip_match:
            ip_guess = ip_match.group(1)

        host = Host(ip=ip_guess, status="up")

        # The collector stores only response headers, so create a canonical
        # web endpoint from the request URL when it is available in the file
        # metadata, otherwise use the host identity as a stable merge target.
        server_str = None
        server_match = re.search(r'(?i)^Server:\s*(.+)$', content, re.MULTILINE)
        if server_match:
            server_str = server_match.group(1).strip()
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
                confidence=Confidence.HIGH,
            )

            # Attach the technology to a WebEndpoint. The previous parser
            # constructed this Technology but never attached it to the model,
            # which caused confirmed server technology to disappear from the
            # WEB TECHNOLOGY report and from service-aware discovery context.
            endpoint_url = None
            url_match = re.search(r'(?im)^(?:Request-URL|URL):\s*(\S+)', content)
            if url_match:
                endpoint_url = url_match.group(1)

            if endpoint_url:
                parsed = urlparse(endpoint_url)
                endpoint = WebEndpoint(
                    url=endpoint_url,
                    path=parsed.path or "/",
                    status_code=None,
                    source=filename,
                    technologies=[tech],
                )
            else:
                scheme = "https" if "443" in filename else "http"
                endpoint_url = f"{scheme}://{ip_guess}" if ip_guess != "unknown" else "http://unknown"
                endpoint = WebEndpoint(
                    url=endpoint_url,
                    path="/",
                    status_code=None,
                    source=filename,
                    technologies=[tech],
                )
            host.web_endpoints.append(endpoint)

            finding = Finding(
                title="HTTP Server Header Disclosed",
                finding_type=FindingType.INFORMATION,
                severity="INFO",
                confidence=Confidence.HIGH,
                description=f"The server identifies itself as: {server_str}",
                source_file=filename,
                source_type="HTTPParser",
                evidence=[Evidence(source_file=filename, source_type="HTTPParser", content=content)],
            )
            host.findings.append(finding)

        if host.web_endpoints or host.findings:
            hosts.append(host)

        return hosts, findings, errors
