from typing import Optional
from reconforge.core.models import Host, WAFAnalysis, Confidence, LowImpactProfile, Evidence
from reconforge.web.waf.detector import WAFDetector

class WAFAnalyzer:
    def analyze_host(self, host: Host) -> Optional[WAFAnalysis]:
        """Analyzes a host's web endpoints and findings to infer WAF presence."""
        # Only analyze if we have web endpoints or findings containing HTTP
        if not host.web_endpoints and not any(f.source_type == "HTTPParser" for f in host.findings):
            return None

        waf = WAFAnalysis()

        # 1. Analyze HTTP Status Codes from Web Endpoints
        for ep in host.web_endpoints:
            if ep.status_code:
                status_str = str(ep.status_code)
                waf.status_counts[status_str] = waf.status_counts.get(status_str, 0) + 1

                # Check for rate limiting
                if ep.status_code == 429:
                    waf.rate_limiting = True
                    waf.detected = True
                    waf.confidence = Confidence.MEDIUM
                    waf.indicators.append("HTTP 429 Too Many Requests observed")

        # 2. Analyze Findings Evidence for Headers/Bodies
        for finding in host.findings:
            if finding.source_type in ["HTTPParser", "WhatWebParser", "HTTP Headers", "WhatWeb"]:
                for ev in finding.evidence:
                    self._analyze_evidence(waf, ev)

        # 3. Analyze WebEndpoint raw paths/categories (like 403s)
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

            # If no provider is found but WAF is detected
            if waf.detected and not waf.provider:
                waf.provider = "Unknown Provider"

            return waf

        return None

    def _analyze_evidence(self, waf: WAFAnalysis, evidence: Evidence):
        """Analyzes a specific piece of evidence for WAF signatures."""
        content = evidence.content

        # Check Retry-After
        if "retry-after:" in content.lower():
            waf.rate_limiting = True
            waf.detected = True
            waf.confidence = Confidence.HIGH
            waf.indicators.append("Retry-After header observed")
            if evidence not in waf.evidence:
                waf.evidence.append(evidence)

        # Run through Detector
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
