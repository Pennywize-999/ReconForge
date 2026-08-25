import ipaddress
from urllib.parse import urlparse
from typing import Optional

from reconforge.core.models import ReconTarget

def is_valid_ip(address: str) -> bool:
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def parse_target(target_input: str, mode: str = "Standard Recon", depth: str = "Common", source: str = "cli") -> ReconTarget:
    """
    Parses a string into a normalized ReconTarget.
    Supports both explicit IPs and URLs.
    """
    input_str = target_input.strip()

    # 1. Check if it's an IP
    if is_valid_ip(input_str):
        return ReconTarget(
            input=input_str,
            target_type="ip",
            ip=input_str,
            hostname=None,
            scheme=None,
            port=None,
            url=None,
            mode=mode,
            depth=depth,
            source=source
        )

    # 2. Check if it's a URL
    if input_str.startswith("http://") or input_str.startswith("https://"):
        parsed_url = urlparse(input_str)
        scheme = parsed_url.scheme
        hostname = parsed_url.hostname
        port = parsed_url.port

        if port is None:
            if scheme == "http":
                port = 80
            elif scheme == "https":
                port = 443

        is_ip = False
        ip_addr = None
        if hostname and is_valid_ip(hostname):
            is_ip = True
            ip_addr = hostname

        return ReconTarget(
            input=input_str,
            target_type="url",
            ip=ip_addr,
            hostname=hostname if not is_ip else None,
            scheme=scheme,
            port=port,
            url=f"{scheme}://{hostname}:{port}" if port else input_str,
            mode=mode,
            depth=depth,
            source=source
        )

    # 3. Fallback
    return ReconTarget(
        input=input_str,
        target_type="unknown",
        ip=None,
        hostname=input_str,
        scheme=None,
        port=None,
        url=None,
        mode=mode,
        depth=depth,
        source=source
    )

