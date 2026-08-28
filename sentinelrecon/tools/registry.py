import shutil
from typing import Dict, List, Optional

from sentinelrecon.tools.models import ToolDefinition


class ToolRegistry:
    """Registry of application capabilities and their underlying providers."""

    def __init__(self):
        self.tools: Dict[str, ToolDefinition] = {}
        self._register_default_tools()

    def _register_default_tools(self):
        self.register(
            ToolDefinition(
                name="nmap",
                category="Network Discovery",
                capability_name="Network Service Discovery",
                provider_name="nmap",
                description="Network Service Discovery & Port Scanning",
                supported_target_types=["ip", "hostname"],
                supported_protocols=["tcp", "udp"],
                input_requirements="IP or hostname",
                output_format="xml",
                parser_name="NmapXMLParser",
                executable="nmap",
            )
        )
        self.register(
            ToolDefinition(
                name="dns_lookup",
                category="DNS Intelligence",
                capability_name="DNS & Reverse Lookup",
                provider_name="dnsutils / host",
                description="DNS and reverse-DNS resolution",
                supported_target_types=["ip", "hostname", "url"],
                supported_protocols=["dns"],
                input_requirements="IP, hostname, or URL",
                output_format="text",
                parser_name="DNSParser",
                executable="host",
            )
        )
        self.register(
            ToolDefinition(
                name="rustscan",
                category="Network Discovery",
                capability_name="Fast Port Scanning",
                provider_name="rustscan",
                description="Fast port scanner",
                supported_target_types=["ip"],
                supported_protocols=["tcp"],
                input_requirements="IP",
                output_format="text",
                parser_name="GenericTextParser",
                executable="rustscan",
            )
        )
        self.register(
            ToolDefinition(
                name="gobuster",
                category="Web Content Discovery",
                capability_name="Web Directory & Content Discovery",
                provider_name="gobuster",
                description="Directory/File & DNS busting tool",
                supported_target_types=["url"],
                supported_protocols=["http", "https"],
                input_requirements="URL",
                output_format="text",
                parser_name="GobusterParser",
                executable="gobuster",
            )
        )
        self.register(
            ToolDefinition(
                name="dirb",
                category="Web Content Discovery",
                capability_name="Web Content Discovery",
                provider_name="dirb",
                description="Web Content Scanner",
                supported_target_types=["url"],
                supported_protocols=["http", "https"],
                input_requirements="URL",
                output_format="text",
                parser_name="DirbParser",
                executable="dirb",
            )
        )
        self.register(
            ToolDefinition(
                name="whatweb",
                category="Technology Fingerprinting",
                capability_name="Web Technology Fingerprinting",
                provider_name="whatweb",
                description="Web technology and framework fingerprinting",
                supported_target_types=["url", "ip", "hostname"],
                supported_protocols=["http", "https"],
                input_requirements="URL or IP",
                output_format="text",
                parser_name="WhatWebParser",
                executable="whatweb",
            )
        )
        self.register(
            ToolDefinition(
                name="feroxbuster",
                category="Web Content Discovery",
                capability_name="Recursive Content Discovery",
                provider_name="feroxbuster",
                description="Fast, simple, recursive content discovery",
                supported_target_types=["url"],
                supported_protocols=["http", "https"],
                input_requirements="URL",
                output_format="text",
                parser_name="GenericTextParser",
                executable="feroxbuster",
            )
        )
        self.register(
            ToolDefinition(
                name="http_collector",
                category="HTTP Response Analysis",
                capability_name="HTTP Response & Header Collector",
                provider_name="SentinelRecon HTTP Collector",
                description="Safe HTTP Information Collector",
                supported_target_types=["url"],
                supported_protocols=["http", "https"],
                input_requirements="URL",
                output_format="text",
                parser_name="HTTPParser",
                executable="http_collector",
            )
        )
        self.register(
            ToolDefinition(
                name="tls_collector",
                category="TLS Analysis",
                capability_name="TLS & Certificate Collector",
                provider_name="SentinelRecon TLS Collector",
                description="Safe TLS Information Collector",
                supported_target_types=["url"],
                supported_protocols=["https"],
                input_requirements="URL",
                output_format="text",
                parser_name="TLSParser",
                executable="tls_collector",
            )
        )

    def register(self, tool: ToolDefinition):
        self.tools[tool.name] = tool

    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        return self.tools.get(name)

    def is_installed(self, tool_name: str) -> bool:
        if tool_name in ["http_collector", "tls_collector"]:
            return True
        tool = self.get_tool(tool_name)
        if not tool:
            return False
        return shutil.which(tool.executable) is not None

    def get_tools_by_category(self) -> Dict[str, List[ToolDefinition]]:
        categories = {}
        for tool in self.tools.values():
            categories.setdefault(tool.category, []).append(tool)
        return categories
