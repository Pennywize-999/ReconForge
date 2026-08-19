from typing import Dict, Optional

def parse_cpe(cpe_str: str) -> Dict[str, Optional[str]]:
    """
    Parse a CPE string (v2.2 or v2.3) and return a dictionary of parts.
    Returns empty/None values if parsing fails.
    """
    result = {
        "vendor": None,
        "product": None,
        "version": None,
        "raw_cpe": cpe_str
    }

    if not cpe_str:
        return result

    cpe_str = cpe_str.lower().strip()

    if cpe_str.startswith("cpe:2.3:"):
        parts = cpe_str.split(":")
        if len(parts) >= 6:
            result["vendor"] = parts[3] if parts[3] != "*" else None
            result["product"] = parts[4] if parts[4] != "*" else None
            result["version"] = parts[5] if parts[5] != "*" else None

    elif cpe_str.startswith("cpe:/"):
        parts = cpe_str.split(":")
        if len(parts) >= 3:
            result["vendor"] = parts[1] if parts[1] else None
            result["product"] = parts[2] if parts[2] else None
            if len(parts) >= 4:
                result["version"] = parts[3] if parts[3] else None

    return result
