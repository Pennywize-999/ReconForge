from abc import ABC, abstractmethod
from typing import List, Tuple
from reconforge.core.models import Host, Finding, WebEndpoint, Vulnerability, Evidence
import os

class BaseParser(ABC):

    @classmethod
    @abstractmethod
    def can_parse(cls, file_path: str) -> bool:
        """Return True if this parser can handle the given file."""
        pass

    @classmethod
    @abstractmethod
    def parse(cls, file_path: str) -> Tuple[List[Host], List[Finding], List[str]]:
        """
        Parse the file and return a tuple of:
        (hosts, generic_findings, errors)
        """
        pass

    @staticmethod
    def read_file_safe(file_path: str) -> str:
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except Exception as e:
            return ""
