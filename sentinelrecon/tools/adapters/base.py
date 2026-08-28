from abc import ABC, abstractmethod
from typing import Optional
from sentinelrecon.core.models import ReconTarget
from sentinelrecon.tools.models import ToolExecutionPlan


class BaseToolAdapter(ABC):
    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def supports_target(self, target: ReconTarget) -> bool:
        pass

    @abstractmethod
    def build_plan(self, target: ReconTarget, output_directory: str, **kwargs) -> Optional[ToolExecutionPlan]:
        pass
