from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from reconforge.core.models import Target, Host, FindingType


class TerminalReporter:
    def __init__(self):
        self.console = Console()

    def report(self, target: Target):
        self.console.print("\n")
        self.console.print(Panel("[bold white]RECONFORGE ANALYSIS REPORT[/bold white]", expand=False, style="cyan"))
        for host in target.hosts.values():
            self._print_target(host)
            self._print_services(host)
            self._print_web(host)
            self._print_tls(host)
            self._print_waf(host)
            self._print_findings(host)
            self._print_vulnerabilities(host)
            self._print_unclassified(host)
        self._print_execution(target)

    def report_waf(self, target: Target):
        self.console.print(Panel("[bold white]RECONFORGE WAF / CDN ANALYSIS[/bold white]", expand=False, style="cyan"))
        for host in target.hosts.values():
            if host.waf_analysis:
                self._print_waf(host)

    def _print_target(self, host: Host):
        self.console.print(f"\n[bold cyan]HOST INFORMATION[/bold cyan]\n{'-' * 60}")
        self.console.print(f"Status:   {host.status}")
        self.console.print(f"IP:       {host.ip}")
        if host.mac: self.console.print(f"MAC:      {host.mac}")
        if host.hostnames: self.console.print(f"Hostname: {', '.join(host.hostnames)}")
        if host.ipv6: self.console.print(f"IPv6:     {host.ipv6}")
        if host.os_guesses: self.console.print(f"OS:       {', '.join(host.os_guesses[:3])}")

    def _print_services(self, host: Host):
        if not host.ports: return
        self.console.print("\n[bold cyan]OPEN PORTS / SERVICES[/bold cyan]\n" + "-" * 60)
        table = Table(box=None, pad_edge=False)
        for col in ("PORT", "STATE", "SERVICE", "PRODUCT", "VERSION"): table.add_column(col)
        for port in sorted(host.ports, key=lambda p: (p.number, p.protocol)):
            service = port.service
            table.add_row(f"{port.number}/{port.protocol}", port.state, service.name if service else "unknown", service.product if service else "", service.version if service else "")
        self.console.print(table)

    def _print_web(self, host: Host):
        if not host.web_endpoints: return
        self.console.print("\n[bold cyan]WEB TECHNOLOGY[/bold cyan]\n" + "-" * 60)
        techs = {}
        for endpoint in host.web_endpoints:
            for tech in endpoint.technologies:
                if tech.name.lower() in {"country", "ip", "title", "httpserver", "url"}:
                    continue
                value = tech.version or (tech.detected_values[0] if tech.detected_values else "")
                techs.setdefault(tech.name, set()).add(value)
        for name, values in sorted(techs.items()):
            clean = ", ".join(v for v in values if v) or "Detected"
            self.console.print(f"{name}: {clean}")
        if not techs:
            self.console.print("No confirmed application technologies detected.")

        self.console.print("\n[bold cyan]DISCOVERED / INTERESTING URLS[/bold cyan]")
        table = Table(box=None, pad_edge=False, expand=True)
        table.add_column("URL", overflow="fold")
        table.add_column("STATUS", justify="right")
        table.add_column("SIGNIFICANCE", overflow="fold")

        seen = set()
        for endpoint in sorted(host.web_endpoints, key=lambda e: (e.url, e.status_code or 0)):
            key = (endpoint.url.rstrip("/"), endpoint.status_code)
            if key in seen:
                continue
            seen.add(key)
            status = endpoint.status_code if endpoint.status_code is not None else "UNKNOWN"
            significance = self._url_significance(endpoint.status_code, endpoint.category)
            table.add_row(endpoint.url, str(status), significance)

        self.console.print(table)

    @staticmethod
    def _url_significance(status, category):
        if status in (200, 201, 204): return "Accessible resource"
        if status in (301, 302, 307, 308): return "Redirect"
        if status == 401: return "Authentication required"
        if status == 403: return "Protected resource"
        if status == 405: return "Method-specific endpoint"
        if status and status >= 500: return "Server/application error"
        if status and status != 404: return "Unusual HTTP response"
        return category or "Observed resource"

    def _print_tls(self, host: Host):
        tls = [f for f in host.findings if f.source_type == "TLSParser"]
        if not tls: return
        self.console.print("\n[bold cyan]TLS / CERTIFICATES[/bold cyan]\n" + "-" * 60)
        for finding in tls: self.console.print(f"{finding.title}: {finding.description}")

    def _print_waf(self, host: Host):
        waf = host.waf_analysis
        if not waf: return
        self.console.print("\n[bold cyan]WAF / CDN ANALYSIS[/bold cyan]\n" + "-" * 60)
        self.console.print(f"Detection:     {'Possible' if waf.detected else 'None'}")
        self.console.print(f"Confidence:    {waf.confidence.value}")
        if waf.provider: self.console.print(f"Provider:      {waf.provider}")
        self.console.print(f"Rate limiting: {'Detected' if waf.rate_limiting else 'None'}")
        for status, count in waf.status_counts.items():
            if status in {"403", "429"}: self.console.print(f"HTTP {status}:    {count}")

    def _print_findings(self, host: Host):
        findings = [f for f in host.findings if f.finding_type != FindingType.VULNERABILITY and f.source_type != "TLSParser"]
        if not findings: return
        self.console.print("\n[bold cyan]IMPORTANT FINDINGS[/bold cyan]\n" + "-" * 60)
        table = Table(box=None, pad_edge=False)
        for col in ("TYPE", "SEVERITY", "CONFIDENCE", "TITLE"): table.add_column(col)
        for finding in findings: table.add_row(finding.finding_type.value, finding.severity, finding.confidence.value, finding.title)
        self.console.print(table)

    def _print_vulnerabilities(self, host: Host):
        if not host.vulnerabilities: return
        self.console.print("\n[bold cyan]VULNERABILITY INTELLIGENCE[/bold cyan]\n" + "-" * 60)
        table = Table(box=None, pad_edge=False)
        for col in ("CVE", "SEVERITY", "CVSS", "CONFIDENCE", "PRODUCT"): table.add_column(col)
        for vuln in host.vulnerabilities: table.add_row(vuln.cve_id or "VULN", vuln.severity, str(vuln.cvss or "N/A"), vuln.confidence.value, vuln.affected_product)
        self.console.print(table)

    def _print_unclassified(self, host: Host):
        if not host.unclassified: return
        self.console.print("\n[bold magenta]UNCLASSIFIED INTELLIGENCE[/bold magenta]\n" + "-" * 60)
        table = Table(box=None, pad_edge=False)
        for col in ("TYPE", "VALUE", "CONTEXT", "POTENTIAL RELEVANCE", "CONFIDENCE"): table.add_column(col)
        for item in host.unclassified:
            table.add_row(item.kind, item.value, item.context[:100], item.potential_relevance, item.confidence.value)
        self.console.print(table)

    def _print_execution(self, target: Target):
        if not target.execution: return
        self.console.print("\n[bold cyan]EXECUTION SUMMARY[/bold cyan]\n" + "-" * 60)
        display_names = {"nmap":"ForgeScan", "http_collector":"ForgeProbe", "whatweb":"ForgeTech", "gobuster":"ForgeDiscover", "dirb":"ForgeDiscover", "tls_collector":"ForgeTLS", "dns_lookup":"ForgeDNS"}
        for info in target.execution:
            tool = display_names.get(info.get("tool", "unknown"), info.get("tool", "unknown"))
            state = "COMPLETED" if info.get("success") else ("TIMEOUT" if info.get("timed_out") else "FAILED")
            self.console.print(f"{tool}: {state}")
