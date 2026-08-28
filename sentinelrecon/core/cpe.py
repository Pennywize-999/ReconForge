from typing import Dict, Optional


def parse_cpe(cpe_str: str) -> Dict[str, Optional[str]]:
    """Parse a CPE 2.3 or 2.2 string into its components."""
    result = {
        "part": None,
        "vendor": None,
        "product": None,
        "version": None,
        "update": None,
        "edition": None,
        "language": None,
        "sw_edition": None,
        "target_sw": None,
        "target_hw": None,
        "other": None,
    }

    if not cpe_str:
        return result

    if cpe_str.startswith("cpe:2.3:"):
        parts = cpe_str.split(":")
        keys = [
            "part",
            "vendor",
            "product",
            "version",
            "update",
            "edition",
            "language",
            "sw_edition",
            "target_sw",
            "target_hw",
            "other",
        ]
        for i, key in enumerate(keys):
            if i + 2 < len(parts):
                val = parts[i + 2]
                result[key] = val if val != "*" else None
    elif cpe_str.startswith("cpe:/"):
        parts = cpe_str[5:].split(":")
        if len(parts) >= 1 and len(parts[0]) == 1:
            result["part"] = parts[0]
        if len(parts) >= 2:
            result["vendor"] = parts[1]
        if len(parts) >= 3:
            result["product"] = parts[2]
        if len(parts) >= 4:
            result["version"] = parts[3]
        if len(parts) >= 5:
            result["update"] = parts[4]

    return result
