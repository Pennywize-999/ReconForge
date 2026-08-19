import os
import re
from typing import List, Tuple
from urllib.parse import urlparse

from reconforge.core.models import Host, Port, Finding, Evidence, WebEndpoint, Technology, Confidence
from reconforge.parsers.base import BaseParser

class WhatWebParser(BaseParser):
    @classmethod
    def can_parse(cls, file_path: str) -> bool:
        if not file_path.endswith('.txt'):
            return False
        content = cls.read_file_safe(file_path)[:500]
        # WhatWeb output usually starts with the URL followed by [200 OK] and plugin info
        return "http" in content and "[" in content and "]" in content and "WhatWeb" not in content # A bit loose, but practical

    @classmethod
    def parse(cls, file_path: str) -> Tuple[List[Host], List[Finding], List[str]]:
        hosts: List[Host] = []
        findings: List[Finding] = []
        errors: List[str] = []

        content = cls.read_file_safe(file_path)
        if not content:
            return hosts, findings, ["Failed to read WhatWeb file"]

        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue

            # Example WhatWeb output:
            # http://10.10.10.25 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)]

            parts = line.split(" [", 1)
            if len(parts) != 2:
                continue

            url = parts[0].strip()
            parsed_url = urlparse(url)
            ip_or_host = parsed_url.hostname

            if not ip_or_host:
                continue

            host = Host(ip="unknown", status="up")
            host.hostnames.append(ip_or_host)

            status_match = re.match(r'(\d{3})', parts[1])
            status_code = int(status_match.group(1)) if status_match else None

            endpoint = WebEndpoint(
                url=url,
                path=parsed_url.path or "/",
                status_code=status_code,
                source=os.path.basename(file_path)
            )

            # Parse plugins
            plugins_raw = parts[1][parts[1].find("]") + 1:].strip()
            # Split by comma not inside brackets
            plugin_parts = re.split(r',\s*(?![^\[]*\])', plugins_raw)

            for p in plugin_parts:
                p = p.strip()
                if not p:
                    continue

                match = re.match(r'([^\[]+)(?:\[(.*)\])?', p)
                if match:
                    name = match.group(1).strip()
                    details = match.group(2)

                    version = None
                    if details:
                        # Sometimes details is just a version, sometimes it's more complex
                        if re.match(r'^[0-9\.]+$', details):
                            version = details

                    tech = Technology(
                        name=name,
                        version=version,
                        sources=[os.path.basename(file_path)],
                        detected_values=[p],
                        confidence=Confidence.HIGH
                    )
                    endpoint.technologies.append(tech)

            host.web_endpoints.append(endpoint)
            hosts.append(host)

        return hosts, findings, errors
