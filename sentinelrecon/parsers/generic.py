from typing import List, Tuple

from sentinelrecon.core.models import Finding, Host
from sentinelrecon.parsers.base import BaseParser


class GenericTextParser(BaseParser):
    @classmethod
    def can_parse(cls, file_path: str) -> bool:
        return file_path.endswith(".txt") or file_path.endswith(".log")

    @classmethod
    def parse(cls, file_path: str) -> Tuple[List[Host], List[Finding], List[str]]:
        hosts: List[Host] = []
        findings: List[Finding] = []
        errors: List[str] = []
        content = cls.read_file_safe(file_path)
        if not content:
            return hosts, findings, ["Failed to read generic file"]
        return hosts, findings, errors
