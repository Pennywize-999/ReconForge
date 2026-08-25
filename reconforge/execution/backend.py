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
        from reconforge.tools.adapters.smb import SmbAdapter
        from reconforge.tools.adapters.dns import DnsAdapter

        self.console = Console()
        self.registry = ToolRegistry()
        self.web_adapters = [GobusterAdapter(), WhatWebAdapter(), DirbAdapter(), HttpCollectorAdapter(), TlsCollectorAdapter()]
        self.service_adapters = [SmbAdapter(), DnsAdapter()]

        from reconforge.execution.executor import ToolExecutor
        from reconforge.core.analyzer import Analyzer
        self.executor = ToolExecutor()
        self.analyzer = Analyzer()

    def execute(self, plan: ReconPlan):
        from reconforge.core.models import ReconTarget
        self.console.print("\n[bold cyan][1/4] Discovery[/bold cyan]")

        results = []

        if plan.target.target_type == "ip":
            nmap_adapter = NmapAdapter()
            tp = nmap_adapter.build_plan(plan.target, plan.output_directory)

            if not self.registry.is_installed(tp.tool):
                self.console.print(f"[-] {nmap_adapter.capability_name}: Required component unavailable")
                results.append(self._create_skipped(tp.tool, plan.target.input, tp.arguments, "Executable not found"))
            else:
                self.console.print(f"[*] {nmap_adapter.capability_name} in progress...")
                result = self.executor.execute(tp)
                results.append(result)
                self._print_result(nmap_adapter.capability_name, result)

            self.console.print("\n[bold cyan][2/4] Service analysis[/bold cyan]")
            analyzed_target = self.analyzer.analyze_directory(plan.output_directory)

            web_targets = []
            service_targets = []
            for ip, host in analyzed_target.hosts.items():
                for port in host.ports:
                    if port.state != "open":
                        continue

                    is_web = False
                    scheme = "http"

                    if port.number in [80, 8080, 8000, 8081]:
                        is_web = True
                        scheme = "http"
                    elif port.number in [443, 8443, 9443]:
                        is_web = True
                        scheme = "https"
                    elif port.service:
                        s_name = (port.service.name or "").lower()
                        s_prod = (port.service.product or "").lower()
                        s_cpe = (port.service.cpe or "").lower()

                        web_keywords = ["http", "www", "web", "nginx", "apache", "lighttpd", "express", "jetty", "tomcat", "gunicorn", "uvicorn", "iis"]
                        if any(kw in s_name or kw in s_prod or kw in s_cpe for kw in web_keywords):
                            is_web = True
                            if any(sec in s_name or sec in s_prod or sec in s_cpe for sec in ["ssl", "https", "tls"]):
                                scheme = "https"

                    if is_web:
                        url = f"{scheme}://{host.ip}:{port.number}"
                        t = ReconTarget(
                            input=url,
                            target_type="url",
                            ip=host.ip,
                            scheme=scheme,
                            port=port.number,
                            url=url,
                            mode=plan.target.mode,
                            depth=getattr(plan.target, "depth", "Common")
                        )
                        web_targets.append(t)

                    # Protocol specific non-web services
                    if port.number in [139, 445] or (port.service and "smb" in (port.service.name or "").lower()):
                        st = ReconTarget(
                            input=host.ip,
                            target_type="ip",
                            ip=host.ip,
                            port=port.number,
                            scheme="smb",
                            mode=plan.target.mode,
                            depth=getattr(plan.target, "depth", "Common")
                        )
                        service_targets.append(st)
                    elif port.number == 53 or (port.service and "dns" in (port.service.name or "").lower()):
                        st = ReconTarget(
                            input=host.ip,
                            target_type="ip",
                            ip=host.ip,
                            hostname=host.hostnames[0] if host.hostnames else None,
                            port=port.number,
                            scheme="dns",
                            mode=plan.target.mode,
                            depth=getattr(plan.target, "depth", "Common")
                        )
                        service_targets.append(st)

            self.console.print("\n[bold cyan][3/4] Adaptive enumeration[/bold cyan]")
            if not web_targets and not service_targets:
                self.console.print("  No active services identified for follow-up enumeration.")

        else:
            self.console.print("\n[bold cyan][2/4] Service analysis[/bold cyan]")
            self.console.print("  URL target detected.")
            self.console.print("\n[bold cyan][3/4] Adaptive enumeration[/bold cyan]")
            web_targets = [plan.target]
            service_targets = []

        for w_target in web_targets:
            for adapter in self.web_adapters:
                if adapter.supports_target(w_target):
                    tp = adapter.build_plan(w_target, plan.output_directory)
                    if not tp:
                        continue

                    if not self.registry.is_installed(tp.tool) and tp.tool not in ["http_collector", "tls_collector", "smb_collector", "dns_collector"]:
                        continue

                    if tp.output_file and w_target.port:
                        base, ext = os.path.splitext(tp.output_file)
                        if w_target.ip:
                            tp.output_file = f"{base}_{w_target.ip}_{w_target.port}{ext}"
                        else:
                            tp.output_file = f"{base}_{w_target.port}{ext}"
                        for i, arg in enumerate(tp.arguments):
                            if arg == base + ext:
                                tp.arguments[i] = tp.output_file

                    self.console.print(f"[*] {adapter.capability_name} on {w_target.url}...")
                    result = self.executor.execute(tp)
                    results.append(result)
                    self._print_result(adapter.capability_name, result)

        for s_target in service_targets:
            for adapter in self.service_adapters:
                if adapter.supports_target(s_target):
                    tp = adapter.build_plan(s_target, plan.output_directory)
                    if not tp:
                        continue
                    self.console.print(f"[*] {adapter.capability_name} on {s_target.ip}:{s_target.port}...")
                    result = self.executor.execute(tp)
                    results.append(result)
                    self._print_result(adapter.capability_name, result)

        exec_file = os.path.join(plan.output_directory, "execution.json")
        with open(exec_file, "w") as f:
            import json
            out = [r.__dict__ for r in results]
            json.dump(out, f, indent=2)

        self.console.print("\n[bold cyan][4/4] Correlation[/bold cyan]")
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
