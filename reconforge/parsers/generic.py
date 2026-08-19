import os
from typing import List, Tuple

from reconforge.core.models import Host, Finding, Evidence, Confidence, FindingType
from reconforge.parsers.base import BaseParser

class GenericTextParser(BaseParser):
    @classmethod
    def can_parse(cls, file_path: str) -> bool:
        return file_path.endswith('.txt') or file_path.endswith('.log')

    @classmethod
    def parse(cls, file_path: str) -> Tuple[List[Host], List[Finding], List[str]]:
        hosts: List[Host] = []
        findings: List[Finding] = []
        errors: List[str] = []

        # This is a fallback parser, it shouldn't produce empty findings.
        # Only parse if there's no other specialized parser, which is handled by analyzer's order.
        content = cls.read_file_safe(file_path)
        if not content:
            return hosts, findings, ["Failed to read generic file"]

        # The Analyzer will automatically attach the file content as Evidence
        # to the overall target since we return empty hosts/findings here.
        # This prevents duplicate "unknown" hosts while preserving the evidence.
        return hosts, findings, errors
