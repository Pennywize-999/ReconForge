from typing import Optional
from sentinelrecon.core.models import Host, WAFAnalysis, Confidence, LowImpactProfile, Evidence
from sentinelrecon.web.waf.detector import WAFDetector


class WAFAnalyzer:
    def analyze_host(self, host: Host) -> Optional[WAFAnalysis]:
        """Analyzes a host's web endpoints and findings to infer WAF presence."""
        if not host.web_endpoints and not any(f.source_type in ["HTTP Response Analysis", "HTTPParser"] for f in host.findings):
            return None

        waf = WAFAnalysis()

        # 1. Analyze HTTP Status Codes from Web Endpoints
        for ep in host.web_endpoints:
            if ep.status_code:
                status_str = str(ep.status_code)
                waf.status_counts[status_str] = waf.status_counts.get(status_str, 0) + 1

                if ep.status_code == 429:
                    waf.rate_limiting = True
                    waf.detected = True
                    waf.confidence = Confidence.MEDIUM
                    waf.indicators.append("HTTP 429 Too Many Requests observed")

        # 2. Analyze Findings Evidence for Headers/Bodies
        for finding in host.findings:
            if finding.source_type in ["HTTP Response Analysis", "HTTPParser", "WhatWebParser", "Technology Fingerprinting", "HTTP Headers"]:
                for ev in finding.evidence:
                    self._analyze_evidence(waf, ev)

        # 3. Analyze WebEndpoint raw paths/categories
        if waf.status_counts.get("403", 0) > 10:
            waf.indicators.append(f"High number of HTTP 403 responses ({waf.status_counts['403']})")
            waf.detected = True
            if waf.confidence == Confidence.UNKNOWN:
                waf.confidence = Confidence.LOW

        # 4. Generate Low Impact Profile if we detected blocking or rate limiting
        if waf.rate_limiting or waf.status_counts.get("403", 0) > 0:
            waf.low_impact_profile = LowImpactProfile()

        if waf.detected or waf.indicators:
            waf.detected = True
            if waf.confidence == Confidence.UNKNOWN:
                waf.confidence = Confidence.LOW

            if waf.detected and not waf.provider:
                waf.provider = "Unknown Provider"

            return waf

        return None

    def analyze(self, host: Host, evidence_list: Optional[list] = None) -> Optional[WAFAnalysis]:
        return self.analyze_host(host)

    def _analyze_evidence(self, waf: WAFAnalysis, evidence: Evidence):
        content = evidence.content

        if "retry-after:" in content.lower():
            waf.rate_limiting = True
            waf.detected = True
            waf.confidence = Confidence.HIGH
            waf.indicators.append("Retry-After header observed")
            if evidence not in waf.evidence:
                waf.evidence.append(evidence)

        provider, conf, indicators = WAFDetector.analyze_headers(content)
        if provider:
            waf.detected = True
            if not waf.provider or WAFDetector._is_higher_confidence(conf, waf.provider_confidence):
                waf.provider = provider
                waf.provider_confidence = conf
                if WAFDetector._is_higher_confidence(conf, waf.confidence):
                    waf.confidence = conf

        for ind in indicators:
            if ind not in waf.indicators:
                waf.indicators.append(ind)
                if evidence not in waf.evidence:
                    waf.evidence.append(evidence)

        provider_body, conf_body, indicators_body = WAFDetector.analyze_body(content)
        if provider_body:
            waf.detected = True
            if not waf.provider or WAFDetector._is_higher_confidence(conf_body, waf.provider_confidence):
                waf.provider = provider_body
                waf.provider_confidence = conf_body
                if WAFDetector._is_higher_confidence(conf_body, waf.confidence):
                    waf.confidence = conf_body

        for ind in indicators_body:
            if ind not in waf.indicators:
                waf.indicators.append(ind)
                if evidence not in waf.evidence:
                    waf.evidence.append(evidence)
