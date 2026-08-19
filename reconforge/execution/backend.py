from abc import ABC, abstractmethod
from typing import List

from reconforge.core.models import ReconPlan
from reconforge.tools.models import ToolExecutionPlan
from reconforge.tools.registry import ToolRegistry
from reconforge.tools.adapters.nmap import NmapAdapter
from reconforge.tools.adapters.gobuster import GobusterAdapter
from reconforge.tools.adapters.whatweb import WhatWebAdapter
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

class ExecutionBackend(ABC):
    @abstractmethod
    def execute(self, plan: ReconPlan):
        pass

class PlanningOnlyBackend(ExecutionBackend):
    def __init__(self):
        self.console = Console()
        self.registry = ToolRegistry()
        self.adapters = [NmapAdapter(), GobusterAdapter(), WhatWebAdapter()]

    def execute(self, plan: ReconPlan):
        """
        Takes a ReconPlan and simply displays what WOULD be executed,
        strictly maintaining the offline analysis architecture.
        Does NOT execute any external network tools.
        """
        self.console.print()
        self.console.print(Panel("TARGET INFORMATION", style="bold cyan", expand=False))
        self.console.print(f"Mode:\n    {plan.mode}")
        self.console.print(f"\nInput:\n    {plan.target.input}")

        if plan.target.scheme:
            self.console.print(f"\nScheme:\n    {plan.target.scheme.upper()}")

        if plan.target.hostname:
            self.console.print(f"\nHost:\n    {plan.target.hostname}")

        if plan.target.ip:
            self.console.print(f"\nIP:\n    {plan.target.ip}")

        if plan.target.port:
            self.console.print(f"\nPort:\n    {plan.target.port}")

        if plan.target.target_type == "url" and not plan.target.hostname:
            self.console.print("\nTarget Type:\n    IP-based URL")
        elif plan.target.target_type == "url":
            self.console.print("\nTarget Type:\n    Hostname-based URL")
        else:
            self.console.print("\nTarget Type:\n    IP")

        self.console.print("\n[bold green]Starting reconnaissance planning...[/bold green]")

        table = Table(title="Planned Reconnaissance Modules")
        table.add_column("Module", style="cyan")
        table.add_column("Constraint", style="magenta")

        for mod in plan.modules:
            constraint = "None"
            if plan.metadata.get("respect_rate_limits"):
                constraint = "Rate Limit Aware"
            table.add_row(mod, constraint)

        self.console.print(table)

        tool_plans: List[ToolExecutionPlan] = []
        for adapter in self.adapters:
            if adapter.supports_target(plan.target):
                tool_plan = adapter.build_plan(plan.target, plan.output_directory)
                tool_plans.append(tool_plan)

        if tool_plans:
            t_table = Table(title="Planned Tool Execution")
            t_table.add_column("Tool", style="cyan")
            t_table.add_column("Arguments", style="yellow")

            for tp in tool_plans:
                t_table.add_row(tp.tool, " ".join(tp.arguments))

            self.console.print(t_table)

        self.console.print("\n[bold yellow]Note: Execution backend is set to PlanningOnlyBackend. No tools were actually executed.[/bold yellow]")
