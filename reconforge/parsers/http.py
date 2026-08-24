import os
import re
from urllib.parse import urlparse
from typing import List, Tuple

from reconforge.core.models import Host, Finding, WebEndpoint, Technology, Confidence, FindingType, Evidence
from reconforge.parsers.base import BaseParser


class HTTPParser(BaseParser):
    @classmethod
    def can_parse(cls, file_path: str) -> bool:
        if not file_path.endswith('.txt'):
            return False
        content = cls.read_file_safe(file_path)[:800]
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
        request_match = re.search(r'(?im)^(?:Request-URL|URL):\s*(\S+)', content)
        endpoint_url = request_match.group(1).strip() if request_match else ""
        parsed = urlparse(endpoint_url) if endpoint_url else None
        host_name = parsed.hostname if parsed else None

        ip_guess = "unknown"
        ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', filename)
        if ip_match:
            ip_guess = ip_match.group(1)
        elif host_name and re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', host_name):
            ip_guess = host_name

        host = Host(ip=ip_guess, status="up")
        if host_name:
            host.hostnames.append(host_name)

        status_match = re.search(r'(?m)^HTTP/1\.\d\s+(\d{3})', content)
        status_code = int(status_match.group(1)) if status_match else None

        endpoint = None
        if endpoint_url:
            endpoint = WebEndpoint(
                url=endpoint_url,
                path=parsed.path or "/",
                status_code=status_code,
                source=filename,
            )

        server_match = re.search(r'(?i)^Server:\s*(.+)$', content, re.MULTILINE)
        if server_match:
            server_str = server_match.group(1).strip()
            parts = server_str.split()
            name = parts[0] if parts else ""
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

            if endpoint is None:
                scheme = "https" if re.search(r'(?i)443', filename) else "http"
                fallback_url = f"{scheme}://{ip_guess}" if ip_guess != "unknown" else "http://unknown"
                endpoint = WebEndpoint(
                    url=fallback_url,
                    path="/",
                    status_code=status_code,
                    source=filename,
                )

            endpoint.technologies.append(tech)

            host.findings.append(Finding(
                title="HTTP Server Header Disclosed",
                finding_type=FindingType.INFORMATION,
                severity="INFO",
                confidence=Confidence.HIGH,
                description=f"The server identifies itself as: {server_str}",
                source_file=filename,
                source_type="HTTPParser",
                evidence=[Evidence(source_file=filename, source_type="HTTPParser", content=content[:12000])],
            ))

        # The HTTP collector stores a bounded response body after the header
        # block. Fingerprint applications that do not identify themselves via
        # Server headers, including qdPM, and retain useful metadata such as
        # generator tags and JavaScript library versions.
        body = content.split("\n\n", 1)[1] if "\n\n" in content else ""
        if endpoint is None and endpoint_url:
            endpoint = WebEndpoint(
                url=endpoint_url,
                path=parsed.path or "/",
                status_code=status_code,
                source=filename,
            )

        if endpoint is not None and body:
            qdpm_match = re.search(r'(?i)\bqdPM\s*(?:v|version)?\s*([0-9]+(?:\.[0-9]+){1,3})?', body)
            if qdpm_match:
                endpoint.technologies.append(Technology(
                    name="qdPM",
                    version=qdpm_match.group(1),
                    sources=[filename],
                    detected_values=[qdpm_match.group(0).strip()],
                    confidence=Confidence.HIGH,
                ))

            generator_match = re.search(
                r'(?is)<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
                body,
            )
            if generator_match:
                generator = generator_match.group(1).strip()
                gm = re.match(r'([^\s/]+(?:\s+[^\s/]+)?)\s*(?:[/ ]\s*([0-9][0-9.\-]*))?$', generator)
                name = gm.group(1) if gm else generator
                version = gm.group(2) if gm else None
                endpoint.technologies.append(Technology(
                    name="MetaGenerator",
                    version=version,
                    sources=[filename],
                    detected_values=[generator],
                    confidence=Confidence.HIGH,
                ))

            jquery_match = re.search(r'(?i)jquery(?:\.min)?[.-]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)', body)
            if jquery_match:
                endpoint.technologies.append(Technology(
                    name="jQuery",
                    version=jquery_match.group(1),
                    sources=[filename],
                    detected_values=[jquery_match.group(0)],
                    confidence=Confidence.HIGH,
                ))

        if endpoint is not None and not any(
            e.url == endpoint.url and e.status_code == endpoint.status_code
            for e in host.web_endpoints
        ):
            host.web_endpoints.append(endpoint)

        if host.web_endpoints or host.findings:
            hosts.append(host)

        return hosts, findings, errors
