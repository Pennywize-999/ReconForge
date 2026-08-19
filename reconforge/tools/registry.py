import shutil
from typing import Dict, List

from reconforge.tools.models import ToolDefinition

class ToolRegistry:
    def __init__(self):
        self.tools: Dict[str, ToolDefinition] = {}
        self._register_default_tools()

    def _register_default_tools(self):
        # Network
        self.register(ToolDefinition(
            name="nmap",
            category="Network",
            description="Network Mapper",
            supported_target_types=["ip", "hostname"],
            supported_protocols=["tcp", "udp"],
            input_requirements="IP or hostname",
            output_format="xml",
            parser_name="NmapXMLParser",
            executable="nmap"
        ))

        self.register(ToolDefinition(
            name="rustscan",
            category="Network",
            description="Fast port scanner",
            supported_target_types=["ip"],
            supported_protocols=["tcp"],
            input_requirements="IP",
            output_format="text",
            parser_name="GenericTextParser",
            executable="rustscan"
        ))

        # Web
        self.register(ToolDefinition(
            name="dirb",
            category="Web",
            description="Web Content Scanner",
            supported_target_types=["url"],
            supported_protocols=["http", "https"],
            input_requirements="URL",
            output_format="text",
            parser_name="DirbParser",
            executable="dirb"
        ))

        self.register(ToolDefinition(
            name="gobuster",
            category="Web",
            description="Directory/File & DNS busting tool",
            supported_target_types=["url"],
            supported_protocols=["http", "https"],
            input_requirements="URL",
            output_format="text",
            parser_name="GobusterParser",
            executable="gobuster"
        ))

        self.register(ToolDefinition(
            name="whatweb",
            category="Web",
            description="Next generation web scanner",
            supported_target_types=["url", "ip", "hostname"],
            supported_protocols=["http", "https"],
            input_requirements="URL or IP",
            output_format="text",
            parser_name="WhatWebParser",
            executable="whatweb"
        ))

        self.register(ToolDefinition(
            name="feroxbuster",
            category="Web",
            description="Fast, simple, recursive content discovery",
            supported_target_types=["url"],
            supported_protocols=["http", "https"],
            input_requirements="URL",
            output_format="text",
            parser_name="GenericTextParser",
            executable="feroxbuster"
        ))

    def register(self, tool: ToolDefinition):
        self.tools[tool.name] = tool

    def get_tool(self, name: str) -> ToolDefinition:
        return self.tools.get(name)

    def is_installed(self, tool_name: str) -> bool:
        tool = self.get_tool(tool_name)
        if not tool:
            return False
        return shutil.which(tool.executable) is not None

    def get_tools_by_category(self) -> Dict[str, List[ToolDefinition]]:
        categories = {}
        for tool in self.tools.values():
            if tool.category not in categories:
                categories[tool.category] = []
            categories[tool.category].append(tool)
        return categories
