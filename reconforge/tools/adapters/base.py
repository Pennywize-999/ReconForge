from abc import ABC, abstractmethod
from typing import List, Dict, Any

from reconforge.core.models import ReconTarget
from reconforge.tools.models import ToolExecutionPlan

class ToolAdapter(ABC):
    """Base interface for all tool adapters."""

    @property
    @abstractmethod
    def tool_name(self) -> str:
        pass

    @property
    def capability_name(self) -> str:
        """Returns the high-level ReconForge capability name for UI display."""
        return self.tool_name

    @property
    @abstractmethod
    def parser_name(self) -> str:
        pass


    @abstractmethod
    def supports_target(self, target: ReconTarget) -> bool:
        """Determines if this tool can be run against the provided target."""
        pass

    @abstractmethod
    def build_plan(self, target: ReconTarget, output_dir: str, **kwargs: Any) -> ToolExecutionPlan:
        """Builds an execution plan containing the tool's arguments and expected output."""
        pass
