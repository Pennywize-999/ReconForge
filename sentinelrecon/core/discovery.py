from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class DiscoveryProfile:
    name: str
    description: str
    default_wordlist: str
    extensions: List[str]
    category_wordlists: List[str]
    max_depth: int = 1
    intensity: str = "balanced"


DISCOVERY_PROFILES: Dict[str, DiscoveryProfile] = {
    "COMMON": DiscoveryProfile(
        name="COMMON",
        description="Standard common path and directory discovery",
        default_wordlist="common.txt",
        extensions=[".php", ".html", ".txt", ".json", ".js"],
        category_wordlists=[
            "categories/admin.txt",
            "categories/api.txt",
            "categories/sensitive_files.txt",
        ],
        max_depth=1,
        intensity="balanced",
    ),
    "MEDIUM": DiscoveryProfile(
        name="MEDIUM",
        description="Expanded web discovery covering standard directories, API endpoints, backups, and configs",
        default_wordlist="medium.txt",
        extensions=[".php", ".html", ".txt", ".json", ".js", ".bak", ".old", ".env", ".config"],
        category_wordlists=[
            "categories/admin.txt",
            "categories/api.txt",
            "categories/sensitive_files.txt",
            "categories/backups.txt",
            "categories/frameworks.txt",
        ],
        max_depth=2,
        intensity="thorough",
    ),
    "DEEP": DiscoveryProfile(
        name="DEEP",
        description="Full multi-category discovery for in-depth authorized assessments",
        default_wordlist="medium.txt",
        extensions=[".php", ".html", ".txt", ".json", ".js", ".bak", ".old", ".env", ".config", ".xml", ".zip", ".tar.gz"],
        category_wordlists=[
            "categories/admin.txt",
            "categories/api.txt",
            "categories/sensitive_files.txt",
            "categories/backups.txt",
            "categories/frameworks.txt",
            "categories/dev_endpoints.txt",
        ],
        max_depth=3,
        intensity="aggressive",
    ),
}


def get_discovery_profile(name: Optional[str]) -> DiscoveryProfile:
    if not name:
        return DISCOVERY_PROFILES["COMMON"]
    return DISCOVERY_PROFILES.get(name.upper(), DISCOVERY_PROFILES["COMMON"])
