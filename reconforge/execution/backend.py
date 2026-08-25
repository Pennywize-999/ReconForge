import os
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
        from reconforge.tools.adapters.dirb import DirbAdapter
        from reconforge.tools.adapters.http_collector import HttpCollectorAdapter
        from reconforge.tools.adapters.tls_collector import TlsCollectorAdapter

        self.web_adapters = [GobusterAdapter(), WhatWebAdapter(), DirbAdapter(), HttpCollectorAdapter(), TlsCollectorAdapter()]

    def execute(self, plan: ReconPlan):
        self.console.print()
        self.console.print(Panel("TARGET INFORMATION", style="bold cyan", expand=False))
        self.console.print(f"Mode:\n    {plan.mode}")
        self.console.print(f"\nInput:\n    {plan.target.input}")

        if plan.target.target_type == "url" and not plan.target.hostname:
            self.console.print("\nTarget Type:\n    IP-based URL")
        elif plan.target.target_type == "url":
            self.console.print("\nTarget Type:\n    Hostname-based URL")
        else:
            self.console.print("\nTarget Type:\n    IP")

        self.console.print("\n[bold green]Starting reconnaissance planning...[/bold green]")

        if plan.target.target_type == "ip":
            self.console.print("\n[bold cyan]PHASE 1: DISCOVERY[/bold cyan]")
            t_table = Table(title="Planned Tool Execution")
            t_table.add_column("Tool", style="cyan")
            t_table.add_column("Arguments", style="yellow")

            nmap_adapter = NmapAdapter()
            tp = nmap_adapter.build_plan(plan.target, plan.output_directory)
            t_table.add_row(tp.tool, " ".join(tp.arguments))
            self.console.print(t_table)

            self.console.print("\n[bold cyan]PHASE 2: SERVICE-AWARE ENUMERATION[/bold cyan]")
            self.console.print("  Follow-up web tools (e.g. Gobuster, WhatWeb, Dirb, HTTP/TLS Collectors)")
            self.console.print("  will be dynamically scheduled for any HTTP/HTTPS services discovered in Phase 1.")

        else:
            self.console.print("\n[bold cyan]SERVICE-AWARE ENUMERATION[/bold cyan]")
            t_table = Table(title="Planned Tool Execution")
            t_table.add_column("Tool", style="cyan")
            t_table.add_column("Arguments", style="yellow")

            for adapter in self.web_adapters:
                if adapter.supports_target(plan.target):
                    tp = adapter.build_plan(plan.target, plan.output_directory)
                    if tp:
                        t_table.add_row(tp.tool, " ".join(tp.arguments))
            self.console.print(t_table)

        self.console.print("\n[bold yellow]Note: Execution backend is set to PlanningOnlyBackend. No tools were actually executed.[/bold yellow]")


class RealExecutionBackend(ExecutionBackend):
    def __init__(self):
        from reconforge.tools.adapters.dirb import DirbAdapter
        from reconforge.tools.adapters.http_collector import HttpCollectorAdapter
        from reconforge.tools.adapters.tls_collector import TlsCollectorAdapter

        self.console = Console()
        self.registry = ToolRegistry()
        self.web_adapters = [GobusterAdapter(), WhatWebAdapter(), DirbAdapter(), HttpCollectorAdapter(), TlsCollectorAdapter()]

        from reconforge.execution.executor import ToolExecutor
        from reconforge.core.analyzer import Analyzer
        self.executor = ToolExecutor()
        self.analyzer = Analyzer()

    def execute(self, plan: ReconPlan):
        from reconforge.core.models import ReconTarget
        self.console.print("\n[bold green]Starting Execution Backend...[/bold green]")

        results = []

        if plan.target.target_type == "ip":
            self.console.print("\n[bold cyan]PHASE 1: DISCOVERY[/bold cyan]")

            nmap_adapter = NmapAdapter()
            tp = nmap_adapter.build_plan(plan.target, plan.output_directory)

            if not self.registry.is_installed(tp.tool):
                self.console.print(f"[SKIP] {tp.tool}\nReason: Executable not found")
                results.append(self._create_skipped(tp.tool, plan.target.input, tp.arguments, "Executable not found"))
            else:
                self.console.print(f"[*] Running {tp.tool}...")
                result = self.executor.execute(tp)
                results.append(result)
                self._print_result(tp.tool, result)

            self.console.print("\n[bold cyan]Parsing Discovery Results...[/bold cyan]")
            analyzed_target = self.analyzer.analyze_directory(plan.output_directory)

            web_targets = []
            for ip, host in analyzed_target.hosts.items():
                for port in host.ports:
                    if port.state != "open":
                        continue

                    is_web = False
                    scheme = "http"

                    if port.number in [80, 8080]:
                        is_web = True
                        scheme = "http"
                    elif port.number in [443, 8443]:
                        is_web = True
                        scheme = "https"
                    elif port.service:
                        s_name = port.service.name.lower() if port.service.name else ""
                        s_prod = port.service.product.lower() if port.service.product else ""
                        if "http" in s_name or "www" in s_name or "http" in s_prod or "www" in s_prod:
                            is_web = True
                            if "ssl" in s_name or "https" in s_name or "ssl" in s_prod or "https" in s_prod:
                                scheme = "https"

                    if is_web:
                        url = f"{scheme}://{host.ip}:{port.number}"
                        t = ReconTarget(input=url, target_type="url", ip=host.ip, scheme=scheme, port=port.number, url=url)
                        web_targets.append(t)

            self.console.print("\n[bold cyan]PHASE 2: SERVICE-AWARE ENUMERATION[/bold cyan]")
            if not web_targets:
                self.console.print("  No web services discovered for follow-up enumeration.")

        else:
            self.console.print("\n[bold cyan]SERVICE-AWARE ENUMERATION[/bold cyan]")
            web_targets = [plan.target]

        for w_target in web_targets:
            for adapter in self.web_adapters:
                if adapter.supports_target(w_target):
                    tp = adapter.build_plan(w_target, plan.output_directory)
                    if not tp:
                        self.console.print(f"[SKIP] {adapter.tool_name}\nReason: Executable/wordlist unavailable")
                        results.append(self._create_skipped(adapter.tool_name, w_target.input, [], "Executable/wordlist unavailable"))
                        continue

                    if not self.registry.is_installed(tp.tool) and tp.tool not in ["http_collector", "tls_collector"]:
                        self.console.print(f"[SKIP] {tp.tool}\nReason: Executable not found")
                        results.append(self._create_skipped(tp.tool, w_target.input, tp.arguments, "Executable not found"))
                        continue

                    self.console.print(f"[*] Running {tp.tool} on {w_target.url}...")

                    if tp.output_file and w_target.port:
                        base, ext = os.path.splitext(tp.output_file)
                        if w_target.ip:
                            tp.output_file = f"{base}_{w_target.ip}_{w_target.port}{ext}"
                        else:
                            tp.output_file = f"{base}_{w_target.port}{ext}"
                        for i, arg in enumerate(tp.arguments):
                            if arg == base + ext:
                                tp.arguments[i] = tp.output_file

                    result = self.executor.execute(tp)
                    results.append(result)
                    self._print_result(tp.tool, result)

        exec_file = os.path.join(plan.output_directory, "execution.json")
        with open(exec_file, "w") as f:
            import json
            out = [r.__dict__ for r in results]
            json.dump(out, f, indent=2)

        self.console.print("\n[bold cyan]Final Parsing and Correlation...[/bold cyan]")
        analyzed_target = self.analyzer.analyze_directory(plan.output_directory)
        return analyzed_target

    def _create_skipped(self, tool, target, args, error):
        from datetime import datetime
        from reconforge.execution.executor import ToolExecutionResult
        return ToolExecutionResult(
            tool=tool, target=target, arguments=args, output_file="",
            return_code=-1, stdout="", stderr=error,
            started_at=datetime.now().isoformat(), finished_at=datetime.now().isoformat(),
            duration=0.0, success=False, timed_out=False, error=error
        )

    def _print_result(self, tool, result):
        if result.success:
            self.console.print(f"[OK] {tool}")
        elif result.timed_out:
            self.console.print(f"[TIMEOUT] {tool}")
        else:
            self.console.print(f"[FAILED] {tool} (Error: {result.error})")
