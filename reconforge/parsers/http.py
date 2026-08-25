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

        techs: List[Technology] = []
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
            techs.append(tech)

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

        # X-Powered-By header
        powered_match = re.search(r'(?i)^X-Powered-By:\s*(.+)$', content, re.MULTILINE)
        if powered_match:
            p_str = powered_match.group(1).strip()
            p_name = p_str.split()[0]
            p_ver = p_name.split("/", 1)[1] if "/" in p_name else None
            p_name = p_name.split("/", 1)[0]
            techs.append(Technology(
                name=p_name,
                version=p_ver,
                sources=[filename],
                detected_values=[p_str],
                confidence=Confidence.HIGH
            ))
            
        # Parse path and status for WebEndpoint
        # Ensure we don't treat HTTP methods like HEAD as paths
        req_match = re.search(r'^(GET|POST|HEAD|PUT|DELETE|OPTIONS)\s+(/[^\s]*)\s+HTTP/1\.[01]', content, re.MULTILINE)
        status_match = re.search(r'^HTTP/1\.[01]\s+(\d{3})', content, re.MULTILINE)
        location_match = re.search(r'(?i)^Location:\s*(.+)$', content, re.MULTILINE)
        
        path = "/"
        if req_match:
            path = req_match.group(2)
            
        status_code = None
        if status_match:
            status_code = int(status_match.group(1))

        redirect_loc = location_match.group(1).strip() if location_match else None
            
        if status_code:
            from reconforge.core.models import WebEndpoint
            category = "Accessible"
            if status_code in [301, 302, 307, 308]:
                category = "Redirect"
            elif status_code in [401, 403]:
                category = "Forbidden"
            elif status_code == 404:
                category = "Not Found"

            endpoint = WebEndpoint(
                url=f"http://{host.ip}{path}" if host.ip != "unknown" else path,
                path=path,
                status_codes=[status_code],
                redirect_location=redirect_loc,
                sources={str(status_code): ["http_collector"]},
                category=category,
                technologies=techs
            )
            host.web_endpoints.append(endpoint)

        if host.findings or host.web_endpoints:
            hosts.append(host)

        return hosts, findings, errors
