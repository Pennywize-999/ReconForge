import re
from typing import Dict, Tuple, Optional
from reconforge.core.models import Confidence

class WAFDetector:
    # Basic signatures mapped to provider name and confidence
    PROVIDERS = {
        "cloudflare": ("Cloudflare", Confidence.HIGH),
        "cf-ray": ("Cloudflare", Confidence.HIGH),
        "__cfduid": ("Cloudflare", Confidence.HIGH),
        "awselb": ("AWS WAF", Confidence.MEDIUM),
        "x-amz-cf-id": ("AWS WAF", Confidence.HIGH),
        "akamai": ("Akamai", Confidence.HIGH),
        "akamaighost": ("Akamai", Confidence.HIGH),
        "incap_ses": ("Imperva", Confidence.HIGH),
        "visid_incap": ("Imperva", Confidence.HIGH),
        "fastly": ("Fastly", Confidence.HIGH),
        "x-fastly": ("Fastly", Confidence.HIGH),
        "azure": ("Azure", Confidence.MEDIUM),
        "x-ms-request-id": ("Azure", Confidence.MEDIUM),
        "sucuri": ("Sucuri", Confidence.HIGH),
        "x-sucuri": ("Sucuri", Confidence.HIGH)
    }

    BLOCKING_PATTERNS = [
        re.compile(r"attention required! \| cloudflare", re.IGNORECASE),
        re.compile(r"please enable cookies", re.IGNORECASE),
        re.compile(r"security by imperva", re.IGNORECASE),
        re.compile(r"access denied", re.IGNORECASE),
        re.compile(r"request blocked", re.IGNORECASE),
        re.compile(r"rate limit exceeded", re.IGNORECASE),
        re.compile(r"captcha", re.IGNORECASE)
    ]

    @classmethod
    def analyze_headers(cls, content: str) -> Tuple[Optional[str], Confidence, list]:
        """Looks for WAF providers in raw HTTP header content."""
        indicators = []
        best_provider = None
        best_conf = Confidence.UNKNOWN

        content_lower = content.lower()

        for signature, (provider, conf) in cls.PROVIDERS.items():
            if signature in content_lower:
                indicators.append(f"Header/Cookie indicator found: {signature}")
                if not best_provider or cls._is_higher_confidence(conf, best_conf):
                    best_provider = provider
                    best_conf = conf

        return best_provider, best_conf, indicators

    @classmethod
    def analyze_body(cls, content: str) -> Tuple[Optional[str], Confidence, list]:
        """Looks for blocking patterns in response bodies."""
        indicators = []
        best_provider = None
        best_conf = Confidence.UNKNOWN

        for pattern in cls.BLOCKING_PATTERNS:
            if pattern.search(content):
                indicators.append(f"Blocking response pattern detected: {pattern.pattern}")

        # If we see cloudflare block pages specifically
        if "cloudflare" in content.lower() and "attention required" in content.lower():
            best_provider = "Cloudflare"
            best_conf = Confidence.HIGH

        return best_provider, best_conf, indicators

    @staticmethod
    def _is_higher_confidence(new_conf: Confidence, old_conf: Confidence) -> bool:
        hierarchy = {
            Confidence.UNKNOWN: 0,
            Confidence.INFO: 1,
            Confidence.LOW: 2,
            Confidence.MEDIUM: 3,
            Confidence.HIGH: 4,
            Confidence.CONFIRMED: 5
        }
        return hierarchy.get(new_conf, 0) > hierarchy.get(old_conf, 0)
