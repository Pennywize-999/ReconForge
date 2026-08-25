from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from reconforge.core.models import Target, Host, Confidence, FindingType

class TerminalReporter:
    def __init__(self):
        self.console = Console()

    def report(self, target: Target):
        self.console.print("\n")
        self.console.print(Panel("[bold white]RECONFORGE ANALYSIS REPORT[/bold white]", expand=False, style="blue"))

        for ip, host in target.hosts.items():
            self._print_target_section(host)
            self._print_services_section(host)
            self._print_web_technology(host)
            self._print_http_info(host)
            self._print_directory_enumeration(host)
            self._print_tls_info(host)
            self._print_waf_analysis(host)
            self._print_findings(host)
            self._print_vulnerabilities(host)

        self._print_execution_section(target)
        self._print_evidence_section(target)

    def report_waf(self, target: Target):
        self.console.print("\n")
        self.console.print(Panel("[bold white]RECONFORGE WAF / CDN ANALYSIS[/bold white]", expand=False, style="blue"))

        for ip, host in target.hosts.items():
            if host.waf_analysis and host.waf_analysis.detected:
                self.console.print(f"\n[bold cyan]TARGET: {host.ip}[/bold cyan]")
                self._print_waf_analysis(host)

    def _print_target_section(self, host: Host):
        self.console.print(f"\n[bold cyan]TARGET: {host.ip}[/bold cyan]")
        self.console.print("-" * 60)
        self.console.print(f"[bold]Status:[/bold] {host.status}")
        if host.mac:
            self.console.print(f"[bold]MAC:[/bold] {host.mac}")
        if host.hostnames:
            self.console.print(f"[bold]Hostname:[/bold] {', '.join(host.hostnames)}")
        if host.ipv6:
            self.console.print(f"[bold]IPv6:[/bold] {host.ipv6}")
        if host.os_guesses or host.os_cpes:
            os_info = host.os_guesses + host.os_cpes
            self.console.print(f"[bold]OS:[/bold] {', '.join(os_info[:3])}")

    def _print_services_section(self, host: Host):
        if not host.ports:
            return
        self.console.print("\n[bold cyan]SERVICES[/bold cyan]")
        self.console.print("-" * 60)
        table = Table(box=None, show_header=True, pad_edge=False)
        table.add_column("PORT", style="bold")
        table.add_column("PROTOCOL")
        table.add_column("SERVICE")
        table.add_column("PRODUCT")
        table.add_column("VERSION")

        for port in host.ports:
            s_name = port.service.name if port.service else "unknown"
            s_product = port.service.product if port.service else ""
            s_version = port.service.version if port.service else ""
            table.add_row(f"{port.number}/{port.protocol}", port.protocol, s_name, s_product, s_version)

        self.console.print(table)

    def _print_web_technology(self, host: Host):
        if not host.web_endpoints:
            return
        techs = set()
        servers = set()
        titles = set()
        for ep in host.web_endpoints:
            for tech in ep.technologies:
                if tech.name == "Server":
                    servers.add(tech.version or tech.detected_values[0] if tech.detected_values else "Unknown")
                elif tech.name == "Title":
                    titles.add(tech.version or tech.detected_values[0] if tech.detected_values else "Unknown")
                else:
                    techs.add(tech.name)

        if servers or techs or titles:
            self.console.print("\n[bold cyan]WEB TECHNOLOGY[/bold cyan]")
            self.console.print("-" * 60)
            if servers:
                self.console.print(f"    Server: {', '.join(servers)}")
            if techs:
                self.console.print(f"    Technologies: {', '.join(techs)}")
            if titles:
                self.console.print(f"    Title: {', '.join(titles)}")

    def _print_http_info(self, host: Host):
        if not host.web_endpoints:
            return

    def _print_http_info(self, host: Host):
        pass # Merged into directory enumeration below

    def _print_directory_enumeration(self, host: Host):
        if not host.web_endpoints:
            return

        self.console.print("\n[bold cyan]DIRECTORY / HTTP ENUMERATION[/bold cyan]")
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Path")
        table.add_column("Status")
        table.add_column("Sources")
        table.add_column("Details")

        for ep in sorted(host.web_endpoints, key=lambda x: x.path):
            statuses = ", ".join(str(s) for s in sorted(ep.status_codes))
            
            all_sources = set()
            for s_list in ep.sources.values():
                all_sources.update(s_list)
            sources_str = ", ".join(sorted(list(all_sources)))
            
            details = ""
            if ep.redirect_location:
                details = f"--> {ep.redirect_location}"
            elif ep.content_length is not None:
                details = f"Size: {ep.content_length}"

            table.add_row(ep.path, statuses, sources_str, details)

        self.console.print(table)
        self.console.print("")

    def _print_tls_info(self, host: Host):
        has_tls = False
        for finding in host.findings:
            if finding.source_type == "TLSParser":
                if not has_tls:
                    self.console.print("\n[bold cyan]TLS[/bold cyan]")
                    self.console.print("-" * 60)
                    has_tls = True
                self.console.print(f"    {finding.title}: {finding.description}")
        if has_tls:
            self.console.print("")

    def _print_waf_analysis(self, host: Host):
        if not host.waf_analysis:
            return
        waf = host.waf_analysis
        self.console.print("\n[bold cyan]WAF / CDN ANALYSIS[/bold cyan]")
        self.console.print("-" * 60)
        self.console.print(f"Detection:       {'[red]Possible[/red]' if waf.detected else 'None'}")
        if waf.provider:
            self.console.print(f"Provider:        {waf.provider} (Confidence: {waf.provider_confidence.value})")
        self.console.print(f"Confidence:      {waf.confidence.value}")
        rate_limit_status = "Detected" if waf.rate_limiting else "None"
        self.console.print(f"Rate limiting:   {rate_limit_status}")
        for status, count in waf.status_counts.items():
            if status in ["403", "429"]:
                self.console.print(f"HTTP {status}:        {count}")
        if waf.low_impact_profile:
            self.console.print("\n[bold]LOW-IMPACT PROFILE RECOMMENDED[/bold]")
            self.console.print("Request policy:  Conservative")
            self.console.print("Respect Retry-After: Yes")

    def _print_findings(self, host: Host):
        display_findings = [f for f in host.findings if f.finding_type != FindingType.VULNERABILITY and f.source_type != "TLSParser"]
        if not display_findings:
            return
        self.console.print("\n[bold cyan]FINDINGS[/bold cyan]")
        self.console.print("-" * 60)
        table = Table(box=None, show_header=True, pad_edge=False)
        table.add_column("TYPE", style="bold")
        table.add_column("SEVERITY")
        table.add_column("TITLE")
        for finding in display_findings:
            table.add_row(finding.finding_type.value, finding.severity, finding.title)
        self.console.print(table)

    def _print_vulnerabilities(self, host: Host):
        if not host.vulnerabilities:
            return
        self.console.print("\n[bold cyan]VULNERABILITY INTELLIGENCE[/bold cyan]")
        self.console.print("-" * 60)
        table = Table(box=None, show_header=True, pad_edge=False)
        table.add_column("CVE", style="bold red")
        table.add_column("SEVERITY", style="bold")
        table.add_column("CVSS")
        table.add_column("CONFIDENCE")
        table.add_column("PRODUCT")
        for vuln in host.vulnerabilities:
            cve = vuln.cve_id or "VULN"
            cvss = str(vuln.cvss) if vuln.cvss else "N/A"
            conf = vuln.confidence.value
            table.add_row(cve, vuln.severity, cvss, conf, vuln.affected_product)
        self.console.print(table)

    def _print_execution_section(self, target: Target):
        if not target.execution:
            return
        self.console.print("\n[bold cyan]EXECUTION[/bold cyan]")
        self.console.print("-" * 60)
        for exec_info in target.execution:
            tool = exec_info.get("tool", "unknown")
            success = exec_info.get("success", False)
            if success:
                self.console.print(f"    {tool}: success")
            elif exec_info.get("timed_out"):
                self.console.print(f"    {tool}: timed_out")
            else:
                self.console.print(f"    {tool}: failed")

    def _print_evidence_section(self, target: Target):
        self.console.print("\n[bold cyan]SESSION EVIDENCE[/bold cyan]")
        self.console.print("-" * 60)
        if not target.evidence:
            self.console.print("  [!] No reconnaissance evidence was collected in this session.")
        else:
            for ev in target.evidence:
                self.console.print(f"  {ev.source_file} ({ev.source_type})")
        self.console.print("\n")
