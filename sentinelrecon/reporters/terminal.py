from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sentinelrecon.core.models import FindingType, Host, Target
from sentinelrecon.vulnerability.engine import VulnerabilityEngine
from sentinelrecon.vulnerability.providers import AUTHORITATIVE_DATASET


class TerminalReporter:
    def __init__(self):
        self.console = Console(highlight=False)

    def report(self, target: Target):
        self.console.print()
        self.console.print(Panel("[bold white]SENTINELRECON ANALYSIS REPORT[/bold white]", expand=False, style="cyan"))
        for host in target.hosts.values():
            self._print_target(host)
            self._print_services(host)
            self._print_web(host)
            self._print_tls(host)
            self._print_waf(host)
            self._print_vulnerabilities(host)
            self._print_findings(host)
            self._print_unclassified(host)

    def report_waf(self, target: Target):
        self.console.print(Panel("[bold white]SENTINELRECON WAF / CDN ANALYSIS[/bold white]", expand=False, style="cyan"))
        for host in target.hosts.values():
            if host.waf_analysis:
                self._print_waf(host)

    def _print_evidence_section(self, target: Target):
        if not target.evidence:
            self.console.print("No reconnaissance evidence was collected.")
            return
        self.console.print("\n[bold cyan]EVIDENCE[/bold cyan]\n" + "-" * 60)
        for ev in target.evidence:
            self.console.print(f"  {ev.source_type}: {ev.source_file}")

    def _print_target(self, host: Host):
        self.console.print(f"\n[bold cyan]TARGET[/bold cyan]\n{'-' * 60}")
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
        self.console.print("\n[bold cyan]SERVICES[/bold cyan]\n" + "-" * 60)
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

        self.console.print("\n[bold cyan]DIRECTORY / HTTP ENUMERATION[/bold cyan]")
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
        tls = [f for f in host.findings if f.source_type in ["TLS Analysis", "TLSParser"]]
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

    def _print_vulnerabilities(self, host: Host):
        self.console.print("\n[bold cyan]VULNERABILITY ASSESSMENT[/bold cyan]\n" + "-" * 60)

        services_count = len([p for p in host.ports if p.service])
        distinct_products = {p.service.product.lower() for p in host.ports if p.service and p.service.product}
        distinct_versions = {p.service.version for p in host.ports if p.service and p.service.version}
        distinct_cpes = {p.service.cpe for p in host.ports if p.service and p.service.cpe}
        vulnerabilities = host.vulnerabilities

        if not vulnerabilities:
            self.console.print("Status: No matching vulnerabilities found")
            self.console.print("No vulnerability matches identified from available evidence.\n")
            self.console.print("Assessment coverage:")
            self.console.print(f"  Services assessed:           {services_count}")
            self.console.print(f"  Services analyzed:           {services_count}")
            self.console.print(f"  Products identified:         {len(distinct_products)}")
            self.console.print(f"  Versions identified:         {len(distinct_versions)}")
            self.console.print(f"  CPEs identified:             {len(distinct_cpes)}")
            self.console.print("  Intelligence sources:        Local Advisories, NVD, CISA KEV")
            self.console.print("  Potential matches:           0")
            self.console.print("  Confirmed vulnerabilities:   0")
            return

        table = Table(box=None, pad_edge=False, show_edge=False, expand=False)
        table.add_column("SEVERITY", no_wrap=True)
        table.add_column("CVE", no_wrap=True)
        table.add_column("PRODUCT", no_wrap=True)
        table.add_column("VERSION", no_wrap=True)
        table.add_column("CONFIDENCE", no_wrap=True)

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}
        for vuln in sorted(vulnerabilities, key=lambda v: (severity_order.get(v.severity, 99), v.cve_id or "")):
            prod = vuln.affected_product
            if vuln.detected_version and prod.endswith(vuln.detected_version):
                prod = prod[: -len(vuln.detected_version)].strip()
            table.add_row(
                vuln.severity,
                vuln.cve_id or "VULN",
                prod or "Unknown",
                vuln.detected_version or "unknown",
                vuln.confidence.value,
            )
        self.console.print(table)

        detail = Table(box=None, pad_edge=False, show_edge=False, expand=False)
        detail.add_column("CVE", no_wrap=True)
        detail.add_column("TITLE", overflow="fold")
        detail.add_column("EVIDENCE", overflow="fold")
        for vuln in vulnerabilities:
            ev_snippet = vuln.evidence[0].content if vuln.evidence else (vuln.description[:80] + "...")
            detail.add_row(
                vuln.cve_id or "VULN",
                vuln.title,
                ev_snippet,
            )
        self.console.print(detail)

        self.console.print("\nAssessment coverage:")
        self.console.print(f"  Services assessed:           {services_count}")
        self.console.print(f"  Services analyzed:           {services_count}")
        self.console.print(f"  Products assessed:           {len(distinct_products)}")
        self.console.print(f"  Products identified:         {len(distinct_products)}")
        self.console.print(f"  Versions identified:         {len(distinct_versions)}")
        self.console.print(f"  CPEs identified:             {len(distinct_cpes)}")
        self.console.print("  Intelligence sources:        Local Advisories, NVD, CISA KEV")
        self.console.print(f"  Potential matches:           {len(vulnerabilities)}")
        self.console.print(f"  Vulnerability records evaluated: {len(AUTHORITATIVE_DATASET)}")
        self.console.print(f"  Vulnerability records eval:  {len(AUTHORITATIVE_DATASET)}")

    def _print_findings(self, host: Host):
        findings = [f for f in host.findings if f.source_type not in ["TLS Analysis", "TLSParser"]]
        if not findings:
            return
        self.console.print("\n[bold cyan]FINDINGS[/bold cyan]\n" + "-" * 60)
        table = Table(box=None, pad_edge=False, show_edge=False, expand=False)
        table.add_column("TYPE", no_wrap=True)
        table.add_column("SEVERITY", no_wrap=True)
        table.add_column("CONFIDENCE", no_wrap=True)
        table.add_column("TITLE", overflow="fold")
        for finding in findings:
            table.add_row(finding.finding_type.value, finding.severity, finding.confidence.value, finding.title)
        self.console.print(table)

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
