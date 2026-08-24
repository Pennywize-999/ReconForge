import os
import re
from typing import List, Tuple
from urllib.parse import urlparse

from reconforge.core.models import Host, Finding, WebEndpoint, Technology, Confidence
from reconforge.parsers.base import BaseParser


class WhatWebParser(BaseParser):
    # WhatWeb plugins that are metadata rather than technology intelligence.
    NON_TECH_PLUGINS = {
        "country", "ip", "title", "httpserver", "url", "html5",
    }

    @classmethod
    def can_parse(cls, file_path: str) -> bool:
        if not file_path.endswith('.txt'):
            return False
        content = cls.read_file_safe(file_path)[:500]
        return "http" in content and "[" in content and "]" in content and "WhatWeb" not in content

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
            parts = line.split(" [", 1)
            if len(parts) != 2:
                continue

            url = parts[0].strip()
            parsed_url = urlparse(url)
            ip_or_host = parsed_url.hostname
            if not ip_or_host:
                continue

            host = Host(ip="unknown", status="up")
            # Preserve the endpoint hostname exactly as WhatWeb reported it.
            # An IP is both the target identity and a useful hostname-like label
            # for compatibility with the existing parser contract and tests.
            host.hostnames.append(ip_or_host)
            if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip_or_host):
                host.ip = ip_or_host

            status_match = re.match(r'(\d{3})', parts[1])
            status_code = int(status_match.group(1)) if status_match else None
            endpoint = WebEndpoint(
                url=url, path=parsed_url.path or "/", status_code=status_code,
                source=os.path.basename(file_path)
            )

            plugins_raw = parts[1][parts[1].find("]") + 1:].strip()
            plugin_parts = re.split(r',\s*(?![^\[]*\])', plugins_raw)
            for plugin in plugin_parts:
                plugin = plugin.strip()
                if not plugin:
                    continue
                match = re.match(r'([^\[]+)(?:\[(.*)\])?', plugin)
                if not match:
                    continue
                name = match.group(1).strip()
                if name.lower() in cls.NON_TECH_PLUGINS:
                    continue
                details = match.group(2)
                version = details if details and re.match(r'^[0-9][0-9.\-]*$', details) else None
                endpoint.technologies.append(Technology(
                    name=name,
                    version=version,
                    sources=[os.path.basename(file_path)],
                    detected_values=[plugin],
                    confidence=Confidence.HIGH,
                ))

            host.web_endpoints.append(endpoint)
            hosts.append(host)

        return hosts, findings, errors
