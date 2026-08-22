import re
from typing import Optional, Tuple

from reconforge.core.models import Vulnerability, Confidence


def parse_cvss_severity(cvss_score: float) -> str:
    if cvss_score >= 9.0:
        return "CRITICAL"
    if cvss_score >= 7.0:
        return "HIGH"
    if cvss_score >= 4.0:
        return "MEDIUM"
    if cvss_score > 0:
        return "LOW"
    return "UNKNOWN"


def _version_tuple(value: str) -> Tuple:
    parts = []
    for token in value.strip().replace("_", ".").replace("-", ".").split("."):
        if token.isdigit():
            parts.append((0, int(token)))
        else:
            parts.append((1, token.lower()))
    return tuple(parts)


def version_matches_range(detected_version: str, affected_range_or_version: str) -> bool:
    """Safely compare a detected version with a simple exact/range expression."""
    if not detected_version or not affected_range_or_version:
        return False
    expression = affected_range_or_version.strip()
    detected = _version_tuple(detected_version)

    match = re.fullmatch(r"(<=|<|>=|>)?\s*([0-9A-Za-z._-]+)", expression)
    if not match:
        return False
    operator, raw_target = match.groups()
    target = _version_tuple(raw_target)
    if operator is None:
        return detected == target
    if operator == "<":
        return detected < target
    if operator == "<=":
        return detected <= target
    if operator == ">":
        return detected > target
    if operator == ">=":
        return detected >= target
    return False


def check_vulnerability_match(vuln: Vulnerability) -> None:
    """Lower confidence unless the detected version is actually inside the supplied range."""
    if vuln.confidence in [Confidence.CONFIRMED, Confidence.HIGH]:
        return
    if vuln.detected_version and vuln.affected_versions:
        if version_matches_range(vuln.detected_version, vuln.affected_versions):
            vuln.confidence = Confidence.MEDIUM
            vuln.description = f"{vuln.description}\n\n[ReconForge]: Version appears inside affected range. Vendor patch/backport status cannot be confirmed."
        else:
            vuln.confidence = Confidence.LOW
            vuln.description = f"{vuln.description}\n\n[ReconForge]: Detected version ({vuln.detected_version}) does not match affected range ({vuln.affected_versions})."
    else:
        vuln.confidence = Confidence.LOW
