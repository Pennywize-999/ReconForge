import os
import re
from typing import List, Tuple
from urllib.parse import urlparse

from reconforge.core.models import Host, WebEndpoint, Finding, Evidence
from reconforge.parsers.base import BaseParser

class GobusterParser(BaseParser):
    @classmethod
    def can_parse(cls, file_path: str) -> bool:
        if not file_path.endswith('.txt'):
            return False
        content = cls.read_file_safe(file_path)[:1000]
        return "Starting gobuster" in content or "Gobuster v" in content or (re.search(r'/\S+\s+\(Status: \d{3}\)', content) is not None)

    @classmethod
    def parse(cls, file_path: str) -> Tuple[List[Host], List[Finding], List[str]]:
        hosts: List[Host] = []
        findings: List[Finding] = []
        errors: List[str] = []

        content = cls.read_file_safe(file_path)
        if not content:
            return hosts, findings, ["Failed to read Gobuster file"]

        target_url = ""
        # Try to find the target URL in gobuster header if present
        for line in content.splitlines():
            if line.startswith("[+] Url:"):
                target_url = line.split(":", 1)[1].strip()
                break

        # If not found in header, we'll try to infer it later in the analyzer
        host = Host(ip="unknown", status="unknown")
        endpoints = []

        # Regex to match: /path (Status: 200) [Size: 123] [--> /redirect]
        pattern = re.compile(r'(/[\w\-\.\/]+)\s+\(Status:\s+(\d{3})\)(?:\s+\[Size:\s+(\d+)\])?(?:\s+\[-->\s+([^\]]+)\])?')

        for line in content.splitlines():
            match = pattern.search(line)
            if match:
                path = match.group(1)
                status = int(match.group(2))
                size = int(match.group(3)) if match.group(3) else None
                redirect = match.group(4) if match.group(4) else None

                category = "Accessible"
                if status in [301, 302, 307, 308]:
                    category = "Redirect"
                elif status in [401, 403]:
                    category = "Forbidden"
                elif status == 404:
                    category = "Not Found"

                full_url = f"{target_url}{path}" if target_url else path

                endpoint = WebEndpoint(
                    url=full_url,
                    path=path,
                    status_code=status,
                    content_length=size,
                    redirect_location=redirect,
                    source="gobuster",
                    category=category
                )
                endpoints.append(endpoint)

        if endpoints:
            # We add to a temporary host object. The analyzer will merge this.
            if target_url:
                parsed_url = urlparse(target_url)
                host.ip = parsed_url.hostname or "unknown"
                host.hostnames.append(host.ip)

            host.web_endpoints = endpoints
            hosts.append(host)

        return hosts, findings, errors

class DirbParser(BaseParser):
    @classmethod
    def can_parse(cls, file_path: str) -> bool:
        if not file_path.endswith('.txt'):
            return False
        content = cls.read_file_safe(file_path)[:500]
        return "DIRB v" in content or "GENERATED WORDS" in content

    @classmethod
    def parse(cls, file_path: str) -> Tuple[List[Host], List[Finding], List[str]]:
        hosts: List[Host] = []
        findings: List[Finding] = []
        errors: List[str] = []

        content = cls.read_file_safe(file_path)
        if not content:
            return hosts, findings, ["Failed to read Dirb file"]

        target_url = ""
        for line in content.splitlines():
            if line.startswith("URL_BASE:"):
                target_url = line.split(":", 1)[1].strip()
                break

        host = Host(ip="unknown", status="unknown")
        endpoints = []

        # Regex to match: + http://10.10.10.25/admin (CODE:200|SIZE:123)
        pattern = re.compile(r'\+\s+(http[s]?://\S+)\s+\(CODE:(\d+)\|SIZE:(\d+)\)')

        for line in content.splitlines():
            match = pattern.search(line)
            if match:
                full_url = match.group(1)
                status = int(match.group(2))
                size = int(match.group(3))

                parsed = urlparse(full_url)
                path = parsed.path or "/"

                category = "Accessible"
                if status in [301, 302, 307, 308]:
                    category = "Redirect"
                elif status in [401, 403]:
                    category = "Forbidden"
                elif status == 404:
                    category = "Not Found"

                endpoint = WebEndpoint(
                    url=full_url,
                    path=path,
                    status_code=status,
                    content_length=size,
                    source="dirb",
                    category=category
                )
                endpoints.append(endpoint)

        if endpoints:
            if target_url:
                parsed_url = urlparse(target_url)
                host.ip = parsed_url.hostname or "unknown"
                host.hostnames.append(host.ip)
            else:
                # Infer from first endpoint
                parsed_url = urlparse(endpoints[0].url)
                host.ip = parsed_url.hostname or "unknown"
                host.hostnames.append(host.ip)

            host.web_endpoints = endpoints
            hosts.append(host)

        return hosts, findings, errors
