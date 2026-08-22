from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Dict, Set


@dataclass(frozen=True)
class DiscoveryCandidate:
    path: str
    category: str
    priority: int = 50


@dataclass
class DiscoveryProfile:
    name: str
    candidates: List[DiscoveryCandidate] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)


class DiscoveryEngine:
    """Build deterministic, category-aware content discovery sets."""

    PROFILE_LIMITS = {"COMMON": 5000, "EXTENDED": 30000, "DEEP": 100000}

    def __init__(self, root: Path | None = None):
        self.root = root or Path(__file__).resolve().parents[1] / "wordlists"

    def load_category(self, category: str) -> List[DiscoveryCandidate]:
        path = self.root / "categories" / f"{category}.txt"
        if not path.exists():
            return []
        result: List[DiscoveryCandidate] = []
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            value = raw.strip()
            if not value or value.startswith("#"):
                continue
            priority = 50
            if value.startswith("!"):
                value = value[1:].strip()
                priority = 90
            result.append(DiscoveryCandidate(value, category, priority))
        return result

    def build(self, profile: str = "COMMON", technologies: Iterable[str] = (), services: Iterable[str] = ()) -> DiscoveryProfile:
        profile = profile.upper()
        if profile not in self.PROFILE_LIMITS:
            raise ValueError("profile must be COMMON, EXTENDED or DEEP")

        selected: List[str] = ["general"]
        if profile in {"EXTENDED", "DEEP"}:
            selected += ["admin", "authentication", "backup", "configuration", "api"]
        if profile == "DEEP":
            selected += ["development", "extensions"]

        tokens = " ".join(list(technologies) + list(services)).lower()
        aliases = {
            "apache": "apache",
            "nginx": "nginx",
            "iis": "iis",
            "php": "php",
            "wordpress": "wordpress",
            "drupal": "drupal",
            "joomla": "joomla",
            "laravel": "laravel",
            "django": "django",
            "flask": "flask",
            "node": "node",
            "express": "node",
            "tomcat": "java",
            "java": "java",
        }
        for token, category in aliases.items():
            if token in tokens and category not in selected:
                selected.append(category)

        seen: Set[str] = set()
        candidates: List[DiscoveryCandidate] = []
        for category in selected:
            for candidate in self.load_category(category):
                normalized = candidate.path.strip().lstrip("/")
                key = normalized.lower()
                if not normalized or key in seen:
                    continue
                seen.add(key)
                candidates.append(DiscoveryCandidate(normalized, candidate.category, candidate.priority))

        candidates.sort(key=lambda item: (-item.priority, item.path.lower()))
        candidates = candidates[: self.PROFILE_LIMITS[profile]]
        return DiscoveryProfile(profile, candidates, selected)

    @staticmethod
    def canonical_url(base_url: str, path: str) -> str:
        return base_url.rstrip("/") + "/" + path.lstrip("/")
