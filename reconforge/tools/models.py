from dataclasses import dataclass, field
from typing import List

@dataclass
class ToolDefinition:
    name: str
    category: str
    description: str
    supported_target_types: List[str]
    supported_protocols: List[str]
    input_requirements: str
    output_format: str
    parser_name: str
    executable: str

@dataclass
class ToolExecutionPlan:
    tool: str
    target: str
    arguments: List[str]
    output_file: str
