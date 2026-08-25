import os
from typing import List, Dict, Optional
from urllib.parse import urlparse

from reconforge.core.models import Target, Host, WebEndpoint, Vulnerability, Finding, Evidence, Technology
from reconforge.parsers.nmap import NmapXMLParser
from reconforge.parsers.web import GobusterParser, DirbParser
from reconforge.parsers.whatweb import WhatWebParser
from reconforge.parsers.http import HTTPParser
from reconforge.parsers.tls import TLSParser
from reconforge.parsers.dns import DNSParser
from reconforge.parsers.smb import SMBParser
from reconforge.parsers.generic import GenericTextParser
from reconforge.web.waf.analyzer import WAFAnalyzer

class Analyzer:
    def __init__(self):
        self.parsers = [
            NmapXMLParser,
            GobusterParser,
            DirbParser,
            WhatWebParser,
            HTTPParser,
            TLSParser,
            DNSParser,
            SMBParser,
            GenericTextParser
        ]

    def analyze_directory(self, directory_path: str) -> Target:
        target = Target()

        metadata_files = {"plan.json", "target.json", "execution.json", "report.json", "report.html"}

        for root, _, files in os.walk(directory_path):
            for file in files:
                if file in metadata_files:
                    continue
                file_path = os.path.join(root, file)
                self.analyze_file(file_path, target)

        # Load execution data if present
        exec_file = os.path.join(directory_path, "execution.json")
        if os.path.exists(exec_file):
            try:
                import json
                with open(exec_file, "r") as f:
                    target.execution = json.load(f)
            except Exception as e:
                print(f"[!] Error loading execution.json: {e}")

        # Post-processing: WAF Analysis
        waf_analyzer = WAFAnalyzer()
        for host in target.hosts.values():
            waf = waf_analyzer.analyze_host(host)
            if waf:
                host.waf_analysis = waf

        return target

    def analyze_file(self, file_path: str, target: Optional[Target] = None) -> Target:
        if target is None:
            target = Target()

        parsed = False
        for parser in self.parsers:
            try:
                if parser.can_parse(file_path):
                    hosts, findings, errors = parser.parse(file_path)

                    # Merge hosts
                    for host in hosts:
                        self._merge_host(target, host)

                    target.evidence.append(Evidence(
                        source_file=file_path,
                        source_type=parser.__name__,
                        content=f"Parsed {len(hosts)} hosts and {len(findings)} findings."
                    ))
                    parsed = True
                    break
            except Exception as e:
                print(f"[!] Error parsing {file_path} with {parser.__name__}: {str(e)}")
                target.evidence.append(Evidence(
                    source_file=file_path,
                    source_type=parser.__name__,
                    content=f"Error parsing file: {str(e)}"
                ))
                parsed = True # Prevent unknown file format warning
                break

        if not parsed:
            print(f"[!] Unknown file format: {file_path}")
            target.evidence.append(Evidence(
                source_file=file_path,
                source_type="Unknown",
                content="File could not be parsed."
            ))

        # Post-processing: WAF Analysis
        waf_analyzer = WAFAnalyzer()
        for host in target.hosts.values():
            waf = waf_analyzer.analyze_host(host)
            if waf:
                host.waf_analysis = waf

        return target

    def _get_endpoint_context(self, ep: WebEndpoint):
        path = ep.path or "/"
        method = (ep.method or "GET").upper()
        scheme = None
        port = None
        if "://" in ep.url:
            parsed = urlparse(ep.url)
            scheme = parsed.scheme
            port = parsed.port
            if not port and scheme:
                port = 443 if scheme == "https" else 80
        return scheme, port, path, method

    def _are_endpoints_equivalent(self, ep1: WebEndpoint, ep2: WebEndpoint) -> bool:
        s1, p1, path1, m1 = self._get_endpoint_context(ep1)
        s2, p2, path2, m2 = self._get_endpoint_context(ep2)

        if path1 != path2 or m1 != m2:
            return False

        if s1 is not None and s2 is not None and p1 is not None and p2 is not None:
            return (s1 == s2) and (p1 == p2)

        return True

    def _merge_host(self, target: Target, new_host: Host):
        # 1. Host Correlation
        existing_host = None

        # Try IP first
        if new_host.ip != "unknown" and new_host.ip in target.hosts:
            existing_host = target.hosts[new_host.ip]

        # Try Hostnames
        if not existing_host:
            for hn in new_host.hostnames:
                for target_host in target.hosts.values():
                    if hn in target_host.hostnames or hn == target_host.ip:
                        existing_host = target_host
                        break
                if existing_host:
                    break

        # 2. Merge Data
        if existing_host:
            # Upgrade IP if unknown
            if existing_host.ip == "unknown" and new_host.ip != "unknown":
                old_key = next((k for k, h in target.hosts.items() if h is existing_host), None)
                if old_key:
                    del target.hosts[old_key]
                existing_host.ip = new_host.ip
                target.hosts[new_host.ip] = existing_host

            if new_host.status != "unknown":
                existing_host.status = new_host.status
            if new_host.ipv6:
                existing_host.ipv6 = new_host.ipv6
            if new_host.mac:
                existing_host.mac = new_host.mac

            for hn in new_host.hostnames:
                if hn not in existing_host.hostnames:
                    existing_host.hostnames.append(hn)

            for os_guess in new_host.os_guesses:
                if os_guess not in existing_host.os_guesses:
                    existing_host.os_guesses.append(os_guess)

            for os_cpe in new_host.os_cpes:
                if os_cpe not in existing_host.os_cpes:
                    existing_host.os_cpes.append(os_cpe)

            # Ports
            for new_port in new_host.ports:
                matched_port = next((p for p in existing_host.ports if p.number == new_port.number and p.protocol == new_port.protocol), None)
                if matched_port:
                    if new_port.service and not matched_port.service:
                        matched_port.service = new_port.service
                    elif new_port.service and matched_port.service:
                        if new_port.service.product and not matched_port.service.product:
                            matched_port.service.product = new_port.service.product
                        if new_port.service.version and not matched_port.service.version:
                            matched_port.service.version = new_port.service.version
                        if new_port.service.cpe and not matched_port.service.cpe:
                            matched_port.service.cpe = new_port.service.cpe
                        self._merge_technologies(matched_port.service.technologies, new_port.service.technologies)
                else:
                    existing_host.ports.append(new_port)

            # Web Endpoints (also correlate to ports)
            for new_endpoint in new_host.web_endpoints:
                # Normalize path without losing trailing slashes
                if new_endpoint.path.startswith("http://") or new_endpoint.path.startswith("https://"):
                    new_endpoint.path = urlparse(new_endpoint.path).path
                
                if not new_endpoint.path:
                    new_endpoint.path = "/"

                # Deduplicate endpoint by context-aware identity strategy
                matched_ep = None
                for ep in existing_host.web_endpoints:
                    if self._are_endpoints_equivalent(ep, new_endpoint):
                        matched_ep = ep
                        break

                if matched_ep:
                    self._merge_technologies(matched_ep.technologies, new_endpoint.technologies)
                    
                    if not matched_ep.redirect_location and new_endpoint.redirect_location:
                        matched_ep.redirect_location = new_endpoint.redirect_location

                    if matched_ep.content_length is None and new_endpoint.content_length is not None:
                        matched_ep.content_length = new_endpoint.content_length

                    if matched_ep.category in ["Accessible", "Other"] and new_endpoint.category not in ["Accessible", "Other"]:
                        matched_ep.category = new_endpoint.category

                    if ("://" not in matched_ep.url) and ("://" in new_endpoint.url):
                        matched_ep.url = new_endpoint.url

                    # Merge status codes and sources
                    for status_code in new_endpoint.status_codes:
                        status_str = str(status_code)
                        if status_code not in matched_ep.status_codes:
                            matched_ep.status_codes.append(status_code)
                            
                        if status_str not in matched_ep.sources:
                            matched_ep.sources[status_str] = []
                            
                        new_sources = new_endpoint.sources.get(status_str, [])
                        for ns in new_sources:
                            if ns not in matched_ep.sources[status_str]:
                                matched_ep.sources[status_str].append(ns)
                else:
                    existing_host.web_endpoints.append(new_endpoint)

            # Vulnerabilities (Deduplicate CVEs)
            for new_vuln in new_host.vulnerabilities:
                if not new_vuln.cve_id:
                    existing_host.vulnerabilities.append(new_vuln)
                    continue

                matched_vuln = next((v for v in existing_host.vulnerabilities if v.cve_id == new_vuln.cve_id), None)
                if matched_vuln:
                    # Merge evidence
                    matched_vuln.evidence.extend(new_vuln.evidence)
                    for ref in new_vuln.references:
                        if ref not in matched_vuln.references:
                            matched_vuln.references.append(ref)
                else:
                    existing_host.vulnerabilities.append(new_vuln)

            # Findings (Merge all new findings)
            for finding in new_host.findings:
                # Basic deduplication by title and source type
                matched_finding = next((f for f in existing_host.findings if f.title == finding.title and f.source_type == finding.source_type), None)
                if matched_finding:
                    matched_finding.evidence.extend(finding.evidence)
                else:
                    existing_host.findings.append(finding)

        else:
            # New Host
            key = new_host.ip
            if key == "unknown" and new_host.hostnames:
                key = new_host.hostnames[0]
            target.hosts[key] = new_host

    def _merge_technologies(self, base_list: List[Technology], new_list: List[Technology]):
        for new_tech in new_list:
            matched = next((t for t in base_list if t.name.lower() == new_tech.name.lower()), None)
            if matched:
                if new_tech.version and not matched.version:
                    matched.version = new_tech.version
                for s in new_tech.sources:
                    if s not in matched.sources:
                        matched.sources.append(s)
                for v in new_tech.detected_values:
                    if v not in matched.detected_values:
                        matched.detected_values.append(v)
            else:
                base_list.append(new_tech)
