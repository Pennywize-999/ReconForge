import ipaddress
import re
from urllib.parse import urlparse
from typing import Optional, Tuple
from sentinelrecon.core.models import ReconTarget


class TargetParser:
    @staticmethod
    def parse(target_str: str) -> ReconTarget:
        target_str = target_str.strip()
        if not target_str:
            raise ValueError("Target cannot be empty")

        if re.match(r"^https?://", target_str, re.I):
            parsed = urlparse(target_str)
            scheme = parsed.scheme.lower()
            hostname = parsed.hostname
            port = parsed.port
            if not port:
                port = 443 if scheme == "https" else 80
            ip_val = None
            if hostname:
                try:
                    ipaddress.ip_address(hostname)
                    ip_val = hostname
                except ValueError:
                    pass
            return ReconTarget(
                input=target_str,
                target_type="url",
                ip=ip_val,
                hostname=hostname if not ip_val else None,
                scheme=scheme,
                port=port,
                url=target_str,
            )

        try:
            ipaddress.ip_address(target_str)
            return ReconTarget(
                input=target_str,
                target_type="ip",
                ip=target_str,
            )
        except ValueError:
            pass

        try:
            ipaddress.ip_network(target_str, strict=False)
            if "/" in target_str:
                return ReconTarget(
                    input=target_str,
                    target_type="network",
                    ip=target_str,
                )
        except ValueError:
            pass

        hostname_pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|^localhost$"
        if re.match(hostname_pattern, target_str):
            return ReconTarget(
                input=target_str,
                target_type="hostname",
                hostname=target_str,
            )

        return ReconTarget(
            input=target_str,
            target_type="unknown",
        )
