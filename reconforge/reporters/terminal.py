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
            self._print_web_endpoints(host)
            self._print_waf_analysis(host)
            self._print_findings(host)
            self._print_vulnerabilities(host)

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

        info = [f"[bold]Status:[/bold] {host.status}"]
        if host.hostnames:
            info.append(f"[bold]Hostnames:[/bold] {', '.join(host.hostnames)}")
        if host.ipv6:
            info.append(f"[bold]IPv6:[/bold] {host.ipv6}")
        if host.mac:
            info.append(f"[bold]MAC:[/bold] {host.mac}")
        if host.os_guesses or host.os_cpes:
            os_info = host.os_guesses + host.os_cpes
            info.append(f"[bold]OS:[/bold] {', '.join(os_info[:3])}")

        for i in info:
            self.console.print(i)

    def _print_services_section(self, host: Host):
        if not host.ports:
            return

        self.console.print("\n[bold cyan]SERVICES[/bold cyan]")
        self.console.print("-" * 60)

        table = Table(box=None, show_header=True, pad_edge=False)
        table.add_column("PORT", style="bold")
        table.add_column("SERVICE")
        table.add_column("PRODUCT")
        table.add_column("VERSION")

        for port in host.ports:
            s_name = port.service.name if port.service else "unknown"
            s_product = port.service.product if port.service else ""
            s_version = port.service.version if port.service else ""
            table.add_row(f"{port.number}/{port.protocol}", s_name, s_product, s_version)

        self.console.print(table)

    def _print_web_endpoints(self, host: Host):
        if not host.web_endpoints:
            return

        self.console.print("\n[bold cyan]WEB ENDPOINTS[/bold cyan]")
        self.console.print("-" * 60)

        table = Table(box=None, show_header=True, pad_edge=False)
        table.add_column("URL", style="bold")
        table.add_column("STATUS")
        table.add_column("CATEGORY")

        for ep in host.web_endpoints:
            status = str(ep.status_code) if ep.status_code else "???"
            table.add_row(ep.url, status, ep.category)

        self.console.print(table)

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
        if not host.findings:
            return

        self.console.print("\n[bold cyan]FINDINGS[/bold cyan]")
        self.console.print("-" * 60)

        table = Table(box=None, show_header=True, pad_edge=False)
        table.add_column("TYPE", style="bold")
        table.add_column("SEVERITY")
        table.add_column("TITLE")

        for finding in host.findings:
            if finding.finding_type == FindingType.VULNERABILITY:
                continue # Handled below
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

    def _print_evidence_section(self, target: Target):
        self.console.print("\n[bold cyan]SESSION EVIDENCE[/bold cyan]")
        self.console.print("-" * 60)
        if not target.evidence:
            self.console.print("  [!] No reconnaissance evidence was collected in this session.")
        else:
            for ev in target.evidence:
                self.console.print(f"  {ev.source_file} ({ev.source_type})")
        self.console.print("\n")
