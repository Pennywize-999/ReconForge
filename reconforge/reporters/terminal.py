from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from reconforge.core.models import Target, Host, FindingType


class TerminalReporter:
    def __init__(self):
        self.console = Console(highlight=False)

    def report(self, target: Target):
        self.console.print()
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

    def report_waf(self, target: Target):
        self.console.print(Panel("[bold white]RECONFORGE WAF / CDN ANALYSIS[/bold white]", expand=False, style="cyan"))
        for host in target.hosts.values():
            if host.waf_analysis:
                self._print_waf(host)

    # Compatibility hook retained for older callers. ReconForge no longer
    # renders raw execution/session evidence in the user-facing report.
    def _print_evidence_section(self, target: Target):
        return None

    def _print_target(self, host: Host):
        self.console.print(f"\n[bold cyan]HOST INFORMATION[/bold cyan]\n{'-' * 60}")
        self.console.print(f"Status:   {host.status}")
        self.console.print(f"IP:       {host.ip}")
        if host.mac:
            self.console.print(f"MAC:      {host.mac}")
        if host.hostnames:
            self.console.print(f"Hostname: {', '.join(host.hostnames)}")
        if host.ipv6:
            self.console.print(f"IPv6:     {host.ipv6}")
        if host.os_guesses:
            self.console.print(f"OS:       {', '.join(host.os_guesses[:3])}")

    def _print_services(self, host: Host):
        if not host.ports:
            return
        self.console.print("\n[bold cyan]OPEN PORTS / SERVICES[/bold cyan]\n" + "-" * 60)
        table = Table(box=None, pad_edge=False, show_edge=False, expand=False)
        for col in ("PORT", "STATE", "SERVICE", "PRODUCT", "VERSION"):
            table.add_column(col, no_wrap=True)
        for port in sorted(host.ports, key=lambda p: (p.number, p.protocol)):
            service = port.service
            table.add_row(
                f"{port.number}/{port.protocol}",
                port.state,
                service.name if service else "unknown",
                service.product if service else "",
                service.version if (service and service.version) else "unknown",
            )
        self.console.print(table)

    def _print_web(self, host: Host):
        if not host.web_endpoints:
            return

        self.console.print("\n[bold cyan]WEB TECHNOLOGY[/bold cyan]\n" + "-" * 60)
        techs = {}
        for endpoint in host.web_endpoints:
            for tech in endpoint.technologies:
                if tech.name.lower() in {"country", "ip", "title", "httpserver", "url"}:
                    continue
                value = tech.version or (tech.detected_values[0] if tech.detected_values else "")
                techs.setdefault(tech.name, set()).add(value)

        if techs:
            for name, values in sorted(techs.items()):
                clean = ", ".join(v for v in values if v) or "Detected"
                self.console.print(f"{name}: {clean}")
        else:
            self.console.print("No confirmed application technologies detected.")

        self.console.print("\n[bold cyan]DISCOVERED / INTERESTING URLS[/bold cyan]")
        table = Table(box=None, pad_edge=False, show_edge=False, expand=False)
        table.add_column("URL", overflow="fold")
        table.add_column("STATUS", justify="right", no_wrap=True)
        table.add_column("SIGNIFICANCE", overflow="fold")

        seen = set()
        for endpoint in sorted(host.web_endpoints, key=lambda e: (e.url, e.status_code or 0)):
            url = endpoint.url.rstrip("/") or endpoint.url
            key = (url, endpoint.status_code)
            if key in seen:
                continue
            seen.add(key)
            status = endpoint.status_code if endpoint.status_code is not None else "UNKNOWN"
            table.add_row(url, str(status), self._url_significance(endpoint.status_code, endpoint.category))

        self.console.print(table)

    @staticmethod
    def _url_significance(status, category):
        if status in (200, 201, 204):
            return "Accessible resource"
        if status in (301, 302, 307, 308):
            return "Redirect"
        if status == 401:
            return "Authentication required"
        if status == 403:
            return "Protected resource"
        if status == 405:
            return "Method-specific endpoint"
        if status and status >= 500:
            return "Server/application error"
        if status and status != 404:
            return "Unusual HTTP response"
        return category or "Observed resource"

    def _print_tls(self, host: Host):
        tls = [f for f in host.findings if f.source_type == "TLSParser"]
        if not tls:
            return
        self.console.print("\n[bold cyan]TLS / CERTIFICATES[/bold cyan]\n" + "-" * 60)
        for finding in tls:
            self.console.print(f"{finding.title}: {finding.description}")

    def _print_waf(self, host: Host):
        waf = host.waf_analysis
        if not waf:
            return
        self.console.print("\n[bold cyan]WAF / CDN ANALYSIS[/bold cyan]\n" + "-" * 60)
        self.console.print(f"Detection:     {'Possible' if waf.detected else 'None'}")
        self.console.print(f"Confidence:    {waf.confidence.value}")
        if waf.provider:
            self.console.print(f"Provider:      {waf.provider}")
        self.console.print(f"Rate limiting: {'Detected' if waf.rate_limiting else 'None'}")
        for status, count in waf.status_counts.items():
            if status in {"403", "429"}:
                self.console.print(f"HTTP {status}:    {count}")

    def _print_findings(self, host: Host):
        findings = [f for f in host.findings if f.finding_type != FindingType.VULNERABILITY and f.source_type != "TLSParser"]
        if not findings:
            return
        self.console.print("\n[bold cyan]IMPORTANT FINDINGS[/bold cyan]\n" + "-" * 60)
        table = Table(box=None, pad_edge=False, show_edge=False, expand=False)
        for col in ("TYPE", "SEVERITY", "CONFIDENCE", "TITLE"):
            table.add_column(col, no_wrap=True)
        for finding in findings:
            table.add_row(finding.finding_type.value, finding.severity, finding.confidence.value, finding.title)
        self.console.print(table)

    def _print_vulnerabilities(self, host: Host):
        # Accept only vulnerability records created by the current verified NVD
        # applicability matcher. Keep the legacy exact-CPE source accepted so
        # reports generated by older sessions remain readable.
        verified_sources = {
            "NVD 2.0 applicability match",
            "NVD 2.0 exact CPE match",
        }
        verified = [
            vuln for vuln in host.vulnerabilities
            if vuln.source in verified_sources
            and vuln.confidence.value == "HIGH"
            and vuln.cpe
            and vuln.detected_version
        ]

        self.console.print("\n[bold cyan]VULNERABILITY INTELLIGENCE[/bold cyan]\n" + "-" * 60)
        if not verified:
            self.console.print("No verified vulnerable CPE matches identified.")
            self.console.print("Only exact versioned CPE applicability matches verified by NVD are reported.")
            return

        table = Table(box=None, pad_edge=False, show_edge=False, expand=False)
        for col in ("CVE", "SEVERITY", "CVSS", "CONFIDENCE", "PRODUCT"):
            table.add_column(col, no_wrap=True)
        for vuln in sorted(verified, key=lambda v: (v.severity, v.cve_id or "")):
            table.add_row(
                vuln.cve_id or "VULN",
                vuln.severity,
                str(vuln.cvss if vuln.cvss is not None else "N/A"),
                vuln.confidence.value,
                vuln.affected_product,
            )
        self.console.print(table)

        detail = Table(box=None, pad_edge=False, show_edge=False, expand=False)
        for col in ("CVE", "DETECTED VERSION", "SOURCE", "REFERENCES"):
            detail.add_column(col, overflow="fold")
        for vuln in verified:
            detail.add_row(
                vuln.cve_id or "VULN",
                vuln.detected_version or "unknown",
                vuln.source or "unknown",
                str(len(vuln.references)),
            )
        self.console.print(detail)

    def _print_unclassified(self, host: Host):
        if not host.unclassified:
            return
        self.console.print("\n[bold magenta]UNCLASSIFIED INTELLIGENCE[/bold magenta]\n" + "-" * 60)
        table = Table(box=None, pad_edge=False, show_edge=False, expand=False)
        for col in ("TYPE", "VALUE", "CONTEXT", "POTENTIAL RELEVANCE", "CONFIDENCE"):
            table.add_column(col, overflow="fold")
        for item in host.unclassified:
            table.add_row(item.kind, item.value, item.context[:100], item.potential_relevance, item.confidence.value)
        self.console.print(table)
