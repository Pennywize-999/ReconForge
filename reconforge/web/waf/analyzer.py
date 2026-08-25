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
        status_counts = {}
        indicators = []
        rate_limiting = False
        provider_detected = None
        provider_confidence = Confidence.UNKNOWN

        # Analyze Endpoints for rate limiting / WAF signs
        for ep in host.web_endpoints:
            for code in ep.status_codes:
                status_str = str(code)
                status_counts[status_str] = status_counts.get(status_str, 0) + 1
                
                if code == 429:
                    rate_limiting = True
                    indicators.append("HTTP 429 Too Many Requests observed")
                elif code in [403, 401]:
                    indicators.append(f"HTTP {code} Access Denied on {ep.path}")

        # Check Technologies for WAF Providers
        waf_providers = ["cloudflare", "incapsula", "akamai", "aws web application firewall", "sucuri"]
        
        # Check endpoints
        for ep in host.web_endpoints:
            for tech in ep.technologies:
                name_lower = tech.name.lower()
                for provider in waf_providers:
                    if provider in name_lower or provider in " ".join(tech.detected_values).lower():
                        provider_detected = tech.name.title() if tech.name.islower() else tech.name
                        provider_confidence = Confidence.HIGH
                        indicators.append(f"WAF Provider '{tech.name}' identified via technology fingerprint")
                        break
                if provider_detected:
                    break
            if provider_detected:
                break
                
        # Also check findings for WAF signatures in headers
        if not provider_detected:
            for finding in host.findings:
                if finding.source_type in ["HTTPParser", "WhatWebParser", "HTTP Headers", "WhatWeb"]:
                    for ev in finding.evidence:
                        content_lower = ev.content.lower()
                        for provider in waf_providers:
                            if provider in content_lower:
                                provider_detected = provider.capitalize()
                                provider_confidence = Confidence.HIGH
                                indicators.append(f"WAF Provider '{provider_detected}' identified in {finding.source_type} evidence")
                                break
                        if provider_detected:
                            break
                if provider_detected:
                    break

        # Heuristics for detection
        # If we have strong provider ID or explicit 429 rate limiting, WAF is confirmed/high
        if provider_detected:
            waf.detected = True
            waf.confidence = Confidence.HIGH
            waf.provider = provider_detected
            waf.provider_confidence = provider_confidence
        elif rate_limiting:
            waf.detected = True
            waf.confidence = Confidence.MEDIUM
            indicators.append("Rate limiting suggests WAF/IPS presence")
        elif status_counts.get("403", 0) > 10:
            # 403 count alone does not confirm WAF, just suspicious
            waf.detected = False
            waf.confidence = Confidence.LOW
            indicators.append("High volume of 403 Forbidden responses, but no definitive WAF signature")
        else:
            waf.detected = False
            waf.confidence = Confidence.INFO

        waf.indicators = indicators
        waf.status_counts = status_counts
        waf.rate_limiting = rate_limiting
        
        if waf.rate_limiting or waf.status_counts.get("403", 0) > 0:
            waf.low_impact_profile = LowImpactProfile()

        if not waf.detected and not waf.indicators:
            return None

        return waf

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
