import re
from typing import Optional
from reconforge.core.models import Vulnerability, Confidence

def parse_cvss_severity(cvss_score: float) -> str:
    if cvss_score >= 9.0:
        return "CRITICAL"
    elif cvss_score >= 7.0:
        return "HIGH"
    elif cvss_score >= 4.0:
        return "MEDIUM"
    elif cvss_score > 0:
        return "LOW"
    return "UNKNOWN"

def version_matches_range(detected_version: str, affected_range_or_version: str) -> bool:
    """
    Very basic version range matcher.
    Handles 'x.y.z', '< x.y.z', '<= x.y.z'
    """
    if not detected_version or not affected_range_or_version:
        return False

    det_parts = [int(p) if p.isdigit() else p for p in re.split(r'[\.\-]', detected_version)]

    match = re.match(r'(<=|<|>=|>)?\s*(.*)', affected_range_or_version.strip())
    if match:
        operator = match.group(1)
        ver = match.group(2)

        tgt_parts = [int(p) if p.isdigit() else p for p in re.split(r'[\.\-]', ver)]

        # Simple equality
        if not operator:
            return detected_version == ver

        # Simplistic range check (only works for numeric parts nicely)
        if operator == '<':
            return det_parts < tgt_parts
        elif operator == '<=':
            return det_parts <= tgt_parts

    return False

def check_vulnerability_match(vuln: Vulnerability) -> None:
    """
    Update confidence and reasoning based on version match.
    """
    if vuln.confidence in [Confidence.CONFIRMED, Confidence.HIGH]:
        return # Already confirmed via direct evidence (e.g. exploit check)

    if vuln.detected_version and vuln.affected_versions:
        is_match = version_matches_range(vuln.detected_version, vuln.affected_versions)
        if is_match:
            vuln.confidence = Confidence.MEDIUM
            vuln.description = f"{vuln.description}\n\n[ReconForge]: Version appears inside affected range. Vendor patch/backport status cannot be confirmed."
        else:
            vuln.confidence = Confidence.LOW
            vuln.description = f"{vuln.description}\n\n[ReconForge]: Detected version ({vuln.detected_version}) does not appear to match affected range ({vuln.affected_versions})."
    else:
        # We don't have enough version info
        vuln.confidence = Confidence.LOW
