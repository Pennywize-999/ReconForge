import os
import re
import base64
import math
from typing import List, Dict, Optional

from reconforge.core.models import Target, Host, WebEndpoint, Vulnerability, Finding, Evidence, Technology, UnclassifiedIntelligence, Confidence
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
        self.parsers = [NmapXMLParser, GobusterParser, DirbParser, WhatWebParser, HTTPParser, TLSParser, DNSParser, SMBParser, GenericTextParser]

    def analyze_directory(self, directory_path: str) -> Target:
        target = Target()
        metadata_files = {"plan.json", "target.json", "execution.json", "report.json", "report.html"}

        for root, _, files in os.walk(directory_path):
            for file in files:
                if file in metadata_files or file.startswith("reconforge_") and file.endswith("_wordlist.txt"):
                    continue
                self.analyze_file(os.path.join(root, file), target)

        exec_file = os.path.join(directory_path, "execution.json")
        if os.path.exists(exec_file):
            try:
                import json
                with open(exec_file, "r", encoding="utf-8", errors="replace") as f:
                    target.execution = json.load(f)
            except Exception as e:
                target.evidence.append(Evidence(exec_file, "ExecutionParser", f"Error loading execution.json: {e}"))

        self._run_waf_analysis(target)
        return target

    def analyze_file(self, file_path: str, target: Optional[Target] = None) -> Target:
        if target is None:
            target = Target()

        parsed = False
        for parser in self.parsers:
            try:
                if parser.can_parse(file_path):
                    hosts, findings, errors = parser.parse(file_path)
                    for host in hosts:
                        self._merge_host(target, host)
                    target.evidence.append(Evidence(file_path, parser.__name__, f"Parsed {len(hosts)} hosts and {len(findings)} findings."))
                    parsed = True
                    break
            except Exception as e:
                target.evidence.append(Evidence(file_path, parser.__name__, f"Error parsing file: {str(e)}"))
                parsed = True
                break

        if not parsed:
            target.evidence.append(Evidence(file_path, "Unknown", "File could not be parsed."))

        self._extract_unclassified(file_path, target)
        self._run_waf_analysis(target)
        return target

    def _run_waf_analysis(self, target: Target):
        waf_analyzer = WAFAnalyzer()
        for host in target.hosts.values():
            waf = waf_analyzer.analyze_host(host)
            if waf:
                host.waf_analysis = waf

    def _extract_unclassified(self, file_path: str, target: Target):
        """Preserve high-signal values that parsers cannot confidently classify."""
        try:
            raw = open(file_path, "r", encoding="utf-8", errors="replace").read()
        except (OSError, UnicodeError):
            return
        if not raw.strip():
            return

        host = next(iter(target.hosts.values()), None)
        if host is None:
            host = Host(ip="unknown", status="unknown")
            target.hosts["unknown"] = host

        candidates: List[UnclassifiedIntelligence] = []
        seen = set()
        for line in raw.splitlines():
            value = re.sub(r"\s+", " ", line).strip()
            if not value or len(value) > 300:
                continue
            lower = value.lower()

            kind = None
            relevance = ""
            confidence = Confidence.UNKNOWN
            extracted = value

            m_hash = re.search(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b", value)
            m_b64 = re.search(r"\b[A-Za-z0-9+/]{20,}={0,2}\b", value)
            credential_context = any(k in lower for k in ("password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "authorization"))
            key_context = any(k in lower for k in ("private key", "client_secret", "access_key", "secret_key"))

            if m_hash:
                extracted = m_hash.group(0)
                kind = "HASH-LIKE"
                relevance = "Potential credential/data artifact"
                confidence = Confidence.MEDIUM
            elif m_b64 and len(m_b64.group(0)) >= 20:
                extracted = m_b64.group(0)
                kind = "ENCODED/TOKEN-LIKE"
                relevance = "Potential encoded value or token"
                confidence = Confidence.LOW
            elif credential_context or key_context:
                match = re.search(r"(?:password|passwd|pwd|secret|token|api[_-]?key|authorization|private key|client_secret|access_key|secret_key)\s*[:=]\s*['\"]?([^'\"\s,;]+)", value, re.I)
                if match:
                    extracted = match.group(1)
                    kind = "CREDENTIAL/SECRET-LIKE"
                    relevance = "Potential credential or secret value"
                    confidence = Confidence.MEDIUM
            elif re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{5,63}", value) and not value.startswith(("http", "www")):
                # Preserve isolated random-looking words/tokens, but avoid dumping ordinary prose.
                if any(ch.isdigit() for ch in value) or "-" in value or "_" in value or len(value) >= 10:
                    extracted = value
                    kind = "UNCLASSIFIED-TEXT"
                    relevance = "Potential identifier, credential candidate, or application value"
                    confidence = Confidence.LOW

            if kind:
                key = (kind, extracted, file_path)
                if key not in seen:
                    seen.add(key)
                    candidates.append(UnclassifiedIntelligence(extracted, kind, context=value[:180], source=file_path, potential_relevance=relevance, confidence=confidence))

        for item in candidates:
            duplicate = next((u for u in host.unclassified if u.kind == item.kind and u.value == item.value), None)
            if duplicate:
                continue
            host.unclassified.append(item)

    def _merge_host(self, target: Target, new_host: Host):
        existing_host = None
        if new_host.ip != "unknown" and new_host.ip in target.hosts:
            existing_host = target.hosts[new_host.ip]

        if not existing_host:
            for hn in new_host.hostnames:
                for target_host in target.hosts.values():
                    if hn in target_host.hostnames or hn == target_host.ip:
                        existing_host = target_host
                        break
                if existing_host:
                    break

        if existing_host:
            if existing_host.ip == "unknown" and new_host.ip != "unknown":
                target.hosts[new_host.ip] = existing_host
                del target.hosts["unknown"]
                existing_host.ip = new_host.ip
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

            for new_port in new_host.ports:
                matched_port = next((p for p in existing_host.ports if p.number == new_port.number and p.protocol == new_port.protocol), None)
                if matched_port:
                    if new_port.service and not matched_port.service:
                        matched_port.service = new_port.service
                    elif new_port.service and matched_port.service:
                        self._merge_technologies(matched_port.service.technologies, new_port.service.technologies)
                else:
                    existing_host.ports.append(new_port)

            for new_endpoint in new_host.web_endpoints:
                matched_ep = next((e for e in existing_host.web_endpoints if e.url == new_endpoint.url and e.status_code == new_endpoint.status_code), None)
                if matched_ep:
                    self._merge_technologies(matched_ep.technologies, new_endpoint.technologies)
                else:
                    existing_host.web_endpoints.append(new_endpoint)

            for new_vuln in new_host.vulnerabilities:
                if not new_vuln.cve_id:
                    existing_host.vulnerabilities.append(new_vuln)
                    continue
                matched_vuln = next((v for v in existing_host.vulnerabilities if v.cve_id == new_vuln.cve_id), None)
                if matched_vuln:
                    matched_vuln.evidence.extend(new_vuln.evidence)
                    for ref in new_vuln.references:
                        if ref not in matched_vuln.references:
                            matched_vuln.references.append(ref)
                else:
                    existing_host.vulnerabilities.append(new_vuln)

            for finding in new_host.findings:
                matched_finding = next((f for f in existing_host.findings if f.title == finding.title and f.source_type == finding.source_type), None)
                if matched_finding:
                    matched_finding.evidence.extend(finding.evidence)
                else:
                    existing_host.findings.append(finding)

            for item in new_host.unclassified:
                if not any(u.kind == item.kind and u.value == item.value for u in existing_host.unclassified):
                    existing_host.unclassified.append(item)
        else:
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
