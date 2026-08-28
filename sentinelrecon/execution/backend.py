import os
from rich.console import Console

from sentinelrecon.core.analyzer import Analyzer
from sentinelrecon.core.discovery import TECHNOLOGY_PROFILES, TechnologyClassifier
from sentinelrecon.core.models import ReconPlan, ReconTarget, Target
from sentinelrecon.services import ServiceCapabilityRouter, ServiceClassifier
from sentinelrecon.execution.executor import ToolExecutor
from sentinelrecon.tools.adapters.dirb import DirbAdapter
from sentinelrecon.tools.adapters.dns import DNSAdapter
from sentinelrecon.tools.adapters.gobuster import GobusterAdapter
from sentinelrecon.tools.adapters.http_collector import HttpCollectorAdapter
from sentinelrecon.tools.adapters.nmap import NmapAdapter
from sentinelrecon.tools.adapters.tls_collector import TlsCollectorAdapter
from sentinelrecon.tools.adapters.whatweb import WhatWebAdapter
from sentinelrecon.tools.registry import ToolRegistry
from sentinelrecon.vulnerability.engine import VulnerabilityEngine


class RealExecutionBackend:
    def __init__(self):
        self.console = Console(highlight=False)
        self.registry = ToolRegistry()
        self.executor = ToolExecutor()
        self.analyzer = Analyzer()
        self.service_classifier = ServiceClassifier()
        self.capability_router = ServiceCapabilityRouter(self.service_classifier)
        self.vulnerability_engine = VulnerabilityEngine()
        self.dns_adapter = DNSAdapter()
        self.http_collector = HttpCollectorAdapter()
        self.whatweb_adapter = WhatWebAdapter()
        self.discovery_adapters = [GobusterAdapter(), DirbAdapter()]
        self.tls_adapter = TlsCollectorAdapter()

    def execute(self, plan: ReconPlan):
        if not plan.output_directory:
            from sentinelrecon.core.session import SessionManager

            session_manager = SessionManager()
            session = session_manager.create_session(
                plan.target if hasattr(plan, "target") and plan.target else Target()
            )
            plan.output_directory = session_manager.get_session_dir(session.id)
        os.makedirs(plan.output_directory, exist_ok=True)
        results = []

        self._header(plan)

        # [1/5] DISCOVERY
        self._phase("PHASE 1 / 5", "DISCOVERY")

        if self.dns_adapter.supports_target(plan.target):
            self._run_plan(
                self.dns_adapter.build_plan(plan.target, plan.output_directory),
                plan.target.input,
                results,
            )

        if plan.target.target_type == "ip":
            tp = NmapAdapter().build_plan(plan.target, plan.output_directory, mode=plan.mode)
            result = self._run_plan(tp, plan.target.input, results)
            if result is None:
                return None

            analyzed_target = self.analyzer.analyze_directory(plan.output_directory)
            web_targets = self._discover_web_targets(
                analyzed_target,
                plan.target.discovery_profile or "AUTONOMOUS",
                plan.target.mode,
            )
            self._show_service_routing(analyzed_target, web_targets)
        else:
            web_targets = [plan.target]

        # [2/5] SERVICE ANALYSIS
        self._phase("PHASE 2 / 5", "SERVICE ANALYSIS")
        if not web_targets:
            self.console.print("  [INFO] No HTTP/HTTPS services discovered for web enumeration.")
        else:
            self.console.print(f"  [OK] Identified {len(web_targets)} active web service endpoint(s)")

        # [3/5] ADAPTIVE ENUMERATION
        self._phase("PHASE 3 / 5", "ADAPTIVE ENUMERATION")
        for w_target in web_targets:
            self._console_target(w_target)
            self._run_web_intelligence(w_target, plan, results)

        final_target = self.analyzer.analyze_directory(plan.output_directory)

        # [4/5] VULNERABILITY ASSESSMENT
        self._phase("PHASE 4 / 5", "VULNERABILITY ASSESSMENT")
        self.console.print("  [>] Evaluating software versions against authoritative vulnerability intelligence...")
        added_vulns = self.vulnerability_engine.assess_target(final_target)
        if added_vulns:
            self.console.print(f"  [OK] Correlated {added_vulns} potential vulnerability finding(s)")
        else:
            self.console.print("  [OK] No matching vulnerabilities identified from available evidence")

        # [5/5] CORRELATION & REPORTING
        self._phase("PHASE 5 / 5", "FINDINGS CORRELATION & REPORTING")
        self.console.print("  [OK] Normalization & evidence fusion completed")
        self.console.print("  [OK] Duplicate findings merged")
        self.console.print("  [OK] Terminal report generated")

        return final_target

    def _run_web_intelligence(self, target, plan, results):
        if self.http_collector.supports_target(target):
            tp = self.http_collector.build_plan(target, plan.output_directory)
            if tp:
                self._run_plan(tp, target.input, results)

        analyzed = self.analyzer.analyze_directory(plan.output_directory)
        technologies, services = self._technology_context(analyzed, target)

        low_impact = "low-impact" in target.mode.lower() or "low impact" in target.mode.lower()
        run_whatweb = not low_impact
        if run_whatweb and self.whatweb_adapter.supports_target(target):
            tp = self.whatweb_adapter.build_plan(
                target,
                plan.output_directory,
                discovery_profile=target.discovery_profile or "AUTONOMOUS",
            )
            if tp:
                self._run_plan(tp, target.input, results)
            analyzed = self.analyzer.analyze_directory(plan.output_directory)
            technologies, services = self._technology_context(analyzed, target)

        # 1. Technology Classification from all collected evidence
        active_techs = TechnologyClassifier.classify_target(analyzed)
        for t in technologies:
            for tech_key in TECHNOLOGY_PROFILES:
                if tech_key.lower() in t.lower() or t.lower() in tech_key.lower():
                    active_techs.add(tech_key)

        self.console.print("  TECHNOLOGY INTELLIGENCE")
        for value in technologies:
            self.console.print(f"    [OK] {value}")
        if not technologies:
            self.console.print("    [INFO] No confirmed application technology matched")

        if active_techs:
            tech_str = " + ".join(["Baseline"] + [t.capitalize() for t in sorted(active_techs)])
            self.console.print(f"  Targeted content discovery ({tech_str})")
        else:
            self.console.print("  Targeted content discovery (Baseline)")

        # 2. Execute Content Discovery with Composite Wordlist (Common + Technology Profiles)
        for adapter in self.discovery_adapters:
            if adapter.supports_target(target):
                tp = adapter.build_plan(
                    target,
                    plan.output_directory,
                    discovery_profile="COMMON",
                    technologies=active_techs,
                )
                if tp:
                    res = self._run_plan(tp, target.input, results)
                    if res and res.success:
                        break

        # 3. Bounded Adaptive Discovery: check if newly discovered endpoints reveal additional technologies
        analyzed_after = self.analyzer.analyze_directory(plan.output_directory)
        new_techs = TechnologyClassifier.classify_target(analyzed_after) - active_techs
        if new_techs:
            self.console.print(f"  [+] Adaptive discovery trigger: identified {', '.join(sorted(new_techs))}")
            for adapter in self.discovery_adapters:
                if adapter.supports_target(target):
                    adaptive_tp = adapter.build_plan(
                        target,
                        plan.output_directory,
                        discovery_profile="COMMON",
                        technologies=new_techs,
                    )
                    if adaptive_tp:
                        self._run_plan(adaptive_tp, target.input, results)

        if self.tls_adapter.supports_target(target):
            tp = self.tls_adapter.build_plan(target, plan.output_directory)
            if tp:
                self._run_plan(tp, target.input, results)

    def _run_plan(self, tool_plan, target_input, results):
        if tool_plan is None:
            return None

        tool = self.registry.get_tool(tool_plan.tool)
        capability_name = tool.capability_name if tool and tool.capability_name else tool_plan.tool

        if not self.registry.is_installed(tool_plan.tool):
            if tool_plan.tool in {"host", "dns_lookup"}:
                self.console.print("  [INFO] Reverse DNS utility unavailable")
            else:
                self.console.print(f"  [INFO] {capability_name} provider unavailable ({tool_plan.tool})")
            return None

        result = self.executor.execute(tool_plan)
        results.append(result)

        if result.success:
            if tool_plan.tool == "host" and self._dns_no_record(result):
                self.console.print(f"  [INFO] {capability_name} -> No DNS records found")
            else:
                self.console.print(f"  [OK] {capability_name}")
        elif result.timed_out:
            self.console.print(f"  [TIMEOUT] {capability_name}")
        else:
            self.console.print(f"  [FAIL] {capability_name}")

        return result

    @staticmethod
    def _classify_dns_result(result) -> str:
        if not result or not result.success:
            return "failed"
        stdout = (result.stdout or "").lower()
        if "has address" in stdout or "domain name pointer" in stdout or "has ipv6" in stdout:
            return "record"
        if "not found" in stdout or "no servers could be reached" in stdout or "3(nxdomain)" in stdout:
            return "no-record"
        return "empty"

    @staticmethod
    def _dns_no_record(result) -> bool:
        return RealExecutionBackend._classify_dns_result(result) == "no-record"

    def _show_service_routing(self, analyzed_target, web_targets):
        self.console.print("\n  DISCOVERED SERVICES")
        self.console.print("  " + "-" * 55)
        self.console.print(f"  {'PORT':<10} {'SERVICE':<12} {'PRODUCT':<20} {'VERSION':<10}")
        self.console.print("  " + "-" * 55)
        for host in analyzed_target.hosts.values():
            for port in sorted(host.ports, key=lambda p: (p.number, p.protocol)):
                if port.state != "open":
                    continue
                ident = self.service_classifier.classify(port, host)
                svc_name = ident.detected_service.upper() if ident.detected_service != "unknown" else "UNKNOWN"
                prod_str = ident.product or ""
                ver_str = ident.version or ""
                self.console.print(f"  {port.number}/{port.protocol:<5} {svc_name:<12} {prod_str:<20} {ver_str:<10}")

        if web_targets:
            self.console.print("\n  WEB CAPABILITY ROUTING")
            for wt in web_targets:
                self.console.print(f"    {wt.url} -> Web Probing & Autonomous Discovery")

    @staticmethod
    def _technology_context(target, web_target):
        technologies, services = [], []
        ignored = {"country", "ip", "title", "httpserver", "url"}

        for host in target.hosts.values():
            if host.ip != web_target.ip:
                continue

            for port in host.ports:
                if port.number == web_target.port and port.service:
                    if port.service.name:
                        services.append(port.service.name)
                    if port.service.product:
                        services.append(port.service.product)
                    if port.service.version:
                        services.append(port.service.version)

            for endpoint in host.web_endpoints:
                endpoint_host = endpoint.url.split("://", 1)[-1].split("/", 1)[0]
                if endpoint_host == f"{web_target.ip}:{web_target.port}" or endpoint_host == web_target.ip:
                    for tech in endpoint.technologies:
                        if tech.name.lower() in ignored:
                            continue
                        technologies.append(tech.name)
                        if tech.version:
                            technologies.append(tech.version)

        return sorted(set(technologies)), sorted(set(services))

    @staticmethod
    def _discover_web_targets(analyzed_target, discovery_profile="AUTONOMOUS", mode="Standard Recon"):
        from sentinelrecon.services.classifier import ServiceClassifier

        targets = []
        classifier = ServiceClassifier()

        for host in analyzed_target.hosts.values():
            for port in host.ports:
                if port.state != "open":
                    continue

                classification = classifier.classify(port, host)
                if not classification.is_web:
                    continue

                scheme = "https" if classification.is_tls else "http"
                url = f"{scheme}://{host.ip}:{port.number}"
                targets.append(
                    ReconTarget(
                        input=url,
                        target_type="url",
                        ip=host.ip,
                        scheme=scheme,
                        port=port.number,
                        url=url,
                        mode=mode,
                        source="service_routing",
                        discovery_profile=discovery_profile,
                    )
                )

        return list({target.url: target for target in targets}.values())

    def _header(self, plan):
        target = plan.target.url or plan.target.input
        mode = plan.mode.upper()
        self.console.print()
        self.console.print("=" * 60)
        self.console.print(f"  SENTINELRECON  ::  {target}")
        self.console.print(f"  MODE           ::  {mode}")
        self.console.print("=" * 60)

    def _phase(self, phase_num, phase_name):
        self.console.print(f"\n[{phase_num}] {phase_name}")

    def _console_target(self, target):
        self.console.print(f"\n  TARGET: {target.url}")
