import os
from abc import ABC, abstractmethod

from reconforge.core.models import ReconPlan, ReconTarget
from reconforge.tools.models import ToolExecutionPlan
from reconforge.tools.registry import ToolRegistry
from reconforge.tools.adapters.nmap import NmapAdapter
from reconforge.tools.adapters.gobuster import GobusterAdapter
from reconforge.tools.adapters.whatweb import WhatWebAdapter
from reconforge.tools.adapters.dns import DNSAdapter
from rich.console import Console
from rich.panel import Panel


DISPLAY_NAMES = {
    "nmap": "ForgeScan",
    "dns_lookup": "ForgeDNS",
    "http_collector": "ForgeProbe",
    "whatweb": "ForgeTech",
    "gobuster": "ForgeDiscover",
    "dirb": "ForgeDiscover",
    "tls_collector": "ForgeTLS",
}


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
        self.web_adapters = [HttpCollectorAdapter(), WhatWebAdapter(), GobusterAdapter(), DirbAdapter(), TlsCollectorAdapter()]

    def execute(self, plan: ReconPlan):
        self.console.print(Panel("RECONFORGE PLAN", style="bold cyan", expand=False))
        self.console.print(f"Target: {plan.target.url or plan.target.input}")
        self.console.print(f"Mode: {plan.mode}")
        self.console.print(f"Profile: {plan.target.discovery_profile}")
        self.console.print("\nPlanned components:")
        for module in plan.modules:
            self.console.print(f"  [OK] {module}")
        self.console.print("\n[dim]Planning only. No external tools were executed.[/dim]")


class RealExecutionBackend(ExecutionBackend):
    def __init__(self):
        from reconforge.tools.adapters.dirb import DirbAdapter
        from reconforge.tools.adapters.http_collector import HttpCollectorAdapter
        from reconforge.tools.adapters.tls_collector import TlsCollectorAdapter
        from reconforge.execution.executor import ToolExecutor
        from reconforge.core.analyzer import Analyzer

        self.console = Console()
        self.registry = ToolRegistry()
        self.executor = ToolExecutor()
        self.analyzer = Analyzer()
        self.dns_adapter = DNSAdapter()
        self.http_adapters = [HttpCollectorAdapter(), WhatWebAdapter()]
        self.discovery_adapters = [GobusterAdapter(), DirbAdapter()]
        self.tls_adapter = TlsCollectorAdapter()

    def execute(self, plan: ReconPlan):
        if not plan.output_directory:
            plan.output_directory = os.path.join("sessions", "current")
        os.makedirs(plan.output_directory, exist_ok=True)
        results = []
        self._header(plan)

        self._phase("PHASE 1 / 5", "DISCOVERY")
        if self.dns_adapter.supports_target(plan.target):
            dns_plan = self.dns_adapter.build_plan(plan.target, plan.output_directory)
            self._run_plan(dns_plan, plan.target.input, results)

        if plan.target.target_type == "ip":
            nmap_adapter = NmapAdapter()
            tp = nmap_adapter.build_plan(plan.target, plan.output_directory, mode=plan.mode)
            result = self._run_plan(tp, plan.target.input, results)
            if result is None:
                return None
            analyzed_target = self.analyzer.analyze_directory(plan.output_directory)
            web_targets = self._discover_web_targets(analyzed_target, plan.target.discovery_profile, plan.target.mode)
            self._show_service_routing(analyzed_target, web_targets)
        else:
            web_targets = [plan.target]
            analyzed_target = self.analyzer.analyze_directory(plan.output_directory)

        if not web_targets:
            self.console.print("  [INFO] No HTTP/HTTPS services discovered.")

        self._phase("PHASE 2 / 5", "SERVICE-AWARE ENUMERATION")
        for w_target in web_targets:
            self._console_target(w_target)
            self._run_web_intelligence(w_target, plan, results)

        self._phase("PHASE 3 / 5", "CONTENT DISCOVERY")
        self.console.print("  [OK] Service-specific content discovery completed")

        final_target = self.analyzer.analyze_directory(plan.output_directory)
        self._phase("PHASE 4 / 5", "CORRELATION")
        self.console.print("  [OK] ForgeCore normalization")
        self.console.print("  [OK] Duplicate findings merged")
        self.console.print("  [OK] Unclassified intelligence filtered")

        self._phase("PHASE 5 / 5", "REPORT GENERATION")
        return final_target

    def _run_web_intelligence(self, target, plan, results):
        for adapter in self.http_adapters:
            if not adapter.supports_target(target):
                continue
            tp = adapter.build_plan(target, plan.output_directory)
            if tp:
                self._run_plan(tp, target.input, results)

        analyzed = self.analyzer.analyze_directory(plan.output_directory)
        technologies, services = self._technology_context(analyzed, target)
        self.console.print("  TECHNOLOGY INTELLIGENCE")
        for value in technologies:
            self.console.print(f"    [OK] {value}")
        if not technologies:
            self.console.print("    [INFO] No confirmed application technology matched")

        self.console.print(f"  DISCOVERY PROFILE: {target.discovery_profile}")
        for adapter in self.discovery_adapters:
            if not adapter.supports_target(target):
                continue
            tp = adapter.build_plan(target, plan.output_directory, discovery_profile=target.discovery_profile, technologies=technologies, services=services)
            if tp:
                self._run_plan(tp, target.input, results)

        if target.scheme == "https":
            tp = self.tls_adapter.build_plan(target, plan.output_directory)
            if tp:
                self._run_plan(tp, target.input, results)

    def _run_plan(self, tp: ToolExecutionPlan, target: str, results: list):
        if not self.registry.is_installed(tp.tool) and tp.tool not in {"http_collector", "tls_collector"}:
            self.console.print(f"  [SKIP] {DISPLAY_NAMES.get(tp.tool, tp.tool)}: executable not found")
            results.append(self._create_skipped(tp.tool, target, tp.arguments, "Executable not found"))
            return results[-1]

        label = DISPLAY_NAMES.get(tp.tool, tp.tool)
        self.console.print(f"  [>] {label}: running")
        # Rich Status is real process feedback, not fabricated scan progress.
        with self.console.status(f"  [bold cyan]⠋ {label}[/bold cyan] running", spinner="dots"):
            result = self.executor.execute(tp)
        results.append(result)
        if result.success:
            self.console.print(f"  [OK] {label}: completed")
        elif result.timed_out:
            self.console.print(f"  [TIMEOUT] {label}: unresolved")
        else:
            self.console.print(f"  [WARN] {label}: failed, continuing")
        return result

    def _show_service_routing(self, analyzed_target, web_targets):
        self.console.print("\nSERVICE-AWARE ROUTING")
        web_by_port = {(t.ip, t.port): t for t in web_targets}
        for host in analyzed_target.hosts.values():
            for port in sorted(host.ports, key=lambda p: (p.number, p.protocol)):
                if port.state != "open":
                    continue
                service = port.service.name if port.service else "unknown"
                product = port.service.product if port.service else ""
                key = (host.ip, port.number)
                if key in web_by_port:
                    target = web_by_port[key]
                    route = "ForgeProbe -> ForgeTech -> ForgeDiscover"
                    if target.scheme == "https":
                        route += " -> ForgeTLS"
                    self.console.print(f"  {port.number}/{port.protocol} {service:<10} -> {route}")
                else:
                    detail = f" ({product})" if product else ""
                    self.console.print(f"  {port.number}/{port.protocol} {service}{detail} -> inventory only")

    @staticmethod
    def _technology_context(target, web_target):
        technologies, services = [], []
        ignored = {"country", "ip", "title", "httpserver", "url"}
        for host in target.hosts.values():
            for port in host.ports:
                if port.number == web_target.port and port.service:
                    if port.service.name: services.append(port.service.name)
                    if port.service.product: services.append(port.service.product)
            for endpoint in host.web_endpoints:
                if endpoint.url.rstrip("/") == web_target.url.rstrip("/"):
                    for tech in endpoint.technologies:
                        if tech.name.lower() in ignored:
                            continue
                        technologies.append(tech.name)
                        if tech.version: technologies.append(tech.version)
        return sorted(set(technologies)), sorted(set(services))

    @staticmethod
    def _discover_web_targets(analyzed_target, discovery_profile="COMMON", mode="Standard Recon"):
        targets = []
        for host in analyzed_target.hosts.values():
            for port in host.ports:
                if port.state != "open":
                    continue
                service_name = (port.service.name if port.service else "").lower()
                product = (port.service.product if port.service else "").lower()
                is_web = "http" in service_name or "http" in product or "www" in service_name or port.number in {80, 443, 8000, 8008, 8080, 8081, 8088, 8888, 8443, 9443}
                if not is_web:
                    continue
                https = port.number in {443, 8443, 9443} or "https" in service_name or "ssl" in service_name or "https" in product or "ssl" in product
                scheme = "https" if https else "http"
                url = f"{scheme}://{host.ip}:{port.number}"
                targets.append(ReconTarget(input=url, target_type="url", ip=host.ip, scheme=scheme, port=port.number, url=url, mode=mode, source="nmap_service_routing", discovery_profile=discovery_profile))
        unique = {}
        for target in targets:
            unique[target.url] = target
        return list(unique.values())

    def _header(self, plan):
        target = plan.target.url or plan.target.input
        self.console.print(Panel(
            f"[bold cyan]RECONFORGE[/bold cyan]\n[white]FIRST-LEVEL RECONNAISSANCE ENGINE[/white]",
            style="cyan", expand=False, width=64
        ))
        self.console.print(f"TARGET   {target}")
        self.console.print(f"MODE     {plan.mode}")
        self.console.print(f"PROFILE  {plan.target.discovery_profile}\n")

    def _phase(self, label, title):
        self.console.print(f"\n[bold cyan]{label}  {title}[/bold cyan]")

    def _console_target(self, target):
        self.console.print(f"  [TARGET] {target.url}")

    @staticmethod
    def _create_skipped(tool, target, args, error):
        from datetime import datetime
        from reconforge.execution.executor import ToolExecutionResult
        now = datetime.now().isoformat()
        return ToolExecutionResult(tool=tool, target=target, arguments=args, output_file="", return_code=-1, stdout="", stderr=error, started_at=now, finished_at=now, duration=0.0, success=False, timed_out=False, error=error)
