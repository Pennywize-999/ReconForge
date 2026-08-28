"""Adaptive technology-aware discovery profiles, registry, and composite wordlist composer."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from sentinelrecon.core.config import load_config
from sentinelrecon.core.models import Host, ReconTarget, Target, WebEndpoint


@dataclass
class DiscoveryProfile:
    name: str
    description: str
    default_wordlist: str
    extensions: List[str]
    category_wordlists: List[str]
    max_depth: int = 1
    intensity: str = "balanced"


@dataclass
class TechnologyProfile:
    name: str
    category: str
    wordlist_file: str
    extensions: List[str]
    description: str = ""


@dataclass
class ServiceProfile:
    name: str
    capability: str
    default_ports: List[int]
    description: str = ""


@dataclass
class DiscoveryDataset:
    category: str
    candidates: List[str] = field(default_factory=list)
    extensions: List[str] = field(default_factory=list)
    priority: int = 50


# Baseline depth profiles (controlling breadth and coverage)
DISCOVERY_PROFILES: Dict[str, DiscoveryProfile] = {
    "COMMON": DiscoveryProfile(
        name="COMMON",
        description="Standard common path and directory discovery baseline",
        default_wordlist="common.txt",
        extensions=[".php", ".html", ".txt", ".json", ".js"],
        category_wordlists=[
            "categories/admin.txt",
            "categories/api.txt",
            "categories/general.txt",
        ],
        max_depth=1,
        intensity="balanced",
    ),
    "MEDIUM": DiscoveryProfile(
        name="MEDIUM",
        description="Expanded web discovery covering standard directories, API endpoints, backups, and configs",
        default_wordlist="extended.txt",
        extensions=[".php", ".html", ".txt", ".json", ".js", ".bak", ".old", ".env", ".config"],
        category_wordlists=[
            "common.txt",
            "extended.txt",
            "categories/admin.txt",
            "categories/api.txt",
            "categories/backup.txt",
            "categories/configuration.txt",
            "categories/general.txt",
        ],
        max_depth=2,
        intensity="thorough",
    ),
    "DEEP": DiscoveryProfile(
        name="DEEP",
        description="Full multi-category discovery for in-depth authorized assessments",
        default_wordlist="deep.txt",
        extensions=[".php", ".html", ".txt", ".json", ".js", ".bak", ".old", ".env", ".config", ".xml", ".zip", ".tar.gz", ".sql"],
        category_wordlists=[
            "common.txt",
            "extended.txt",
            "deep.txt",
            "categories/admin.txt",
            "categories/api.txt",
            "categories/backup.txt",
            "categories/configuration.txt",
            "categories/general.txt",
        ],
        max_depth=3,
        intensity="aggressive",
    ),
    "AUTONOMOUS": DiscoveryProfile(
        name="AUTONOMOUS",
        description="Autonomous adaptive discovery composed of Common baseline + detected technology profiles",
        default_wordlist="common.txt",
        extensions=[".php", ".html", ".txt", ".json", ".js"],
        category_wordlists=[
            "categories/admin.txt",
            "categories/api.txt",
            "categories/general.txt",
        ],
        max_depth=2,
        intensity="adaptive",
    ),
}

# Technology-specific wordlists mapped to fingerprints
TECHNOLOGY_PROFILES: Dict[str, TechnologyProfile] = {
    "WORDPRESS": TechnologyProfile(
        name="WORDPRESS",
        category="CMS",
        wordlist_file="categories/wordpress.txt",
        extensions=[".php", ".txt", ".bak"],
        description="WordPress core paths, login, admin, content, and plugin endpoints",
    ),
    "TOMCAT": TechnologyProfile(
        name="TOMCAT",
        category="Application Server",
        wordlist_file="categories/tomcat.txt",
        extensions=[".jsp", ".html", ".txt", ".xml"],
        description="Apache Tomcat management, status, examples, and documentation endpoints",
    ),
    "APACHE": TechnologyProfile(
        name="APACHE",
        category="Web Server",
        wordlist_file="categories/apache.txt",
        extensions=[".html", ".htm", ".cgi", ".pl"],
        description="Apache HTTP Server status, icons, manual, and configuration paths",
    ),
    "NGINX": TechnologyProfile(
        name="NGINX",
        category="Web Server",
        wordlist_file="categories/nginx.txt",
        extensions=[".html", ".conf"],
        description="Nginx status, default pages, and configuration paths",
    ),
    "PHP": TechnologyProfile(
        name="PHP",
        category="Language/Runtime",
        wordlist_file="categories/php.txt",
        extensions=[".php", ".php5", ".phtml", ".inc"],
        description="PHP info, test, configuration, and composer endpoints",
    ),
    "JOOMLA": TechnologyProfile(
        name="JOOMLA",
        category="CMS",
        wordlist_file="categories/joomla.txt",
        extensions=[".php", ".xml", ".txt"],
        description="Joomla administrator, components, modules, and installation paths",
    ),
    "DRUPAL": TechnologyProfile(
        name="DRUPAL",
        category="CMS",
        wordlist_file="categories/drupal.txt",
        extensions=[".php", ".txt", ".yml"],
        description="Drupal core, modules, themes, and configuration paths",
    ),
    "SPRING": TechnologyProfile(
        name="SPRING",
        category="Framework",
        wordlist_file="categories/spring.txt",
        extensions=[".json", ".html"],
        description="Spring Boot Actuators, swagger-ui, and heap/env endpoints",
    ),
    "LARAVEL": TechnologyProfile(
        name="LARAVEL",
        category="Framework",
        wordlist_file="categories/laravel.txt",
        extensions=[".php", ".log", ".env"],
        description="Laravel logs, artisan, telescope, and storage paths",
    ),
    "DJANGO": TechnologyProfile(
        name="DJANGO",
        category="Framework",
        wordlist_file="categories/django.txt",
        extensions=[".html", ".json"],
        description="Django admin, static assets, and debug endpoints",
    ),
    "ASPNET": TechnologyProfile(
        name="ASPNET",
        category="Framework",
        wordlist_file="categories/aspnet.txt",
        extensions=[".aspx", ".asmx", ".ashx", ".axd", ".config"],
        description="ASP.NET Web.config, elmah.axd, trace.axd, and API routes",
    ),
    "NODE": TechnologyProfile(
        name="NODE",
        category="Language/Runtime",
        wordlist_file="categories/node.txt",
        extensions=[".js", ".json"],
        description="Node.js package.json, npm debug logs, and server entrypoints",
    ),
}

# Supported service profiles
SERVICE_PROFILES: Dict[str, ServiceProfile] = {
    "HTTP": ServiceProfile("HTTP", "WEB", [80, 8080, 8000], "HTTP Web Service"),
    "HTTPS": ServiceProfile("HTTPS", "WEB", [443, 8443], "HTTPS Web Service"),
    "SSH": ServiceProfile("SSH", "SSH", [22, 2222], "SSH Secure Shell"),
    "AJP": ServiceProfile("AJP", "AJP", [8009], "Apache JServ Protocol"),
    "SMB": ServiceProfile("SMB", "SMB", [445, 139], "SMB Windows File Sharing"),
    "DNS": ServiceProfile("DNS", "DNS", [53], "Domain Name System"),
    "FTP": ServiceProfile("FTP", "FTP", [21], "File Transfer Protocol"),
    "SMTP": ServiceProfile("SMTP", "SMTP", [25, 587], "Simple Mail Transfer Protocol"),
    "SNMP": ServiceProfile("SNMP", "SNMP", [161], "Simple Network Management Protocol"),
    "LDAP": ServiceProfile("LDAP", "LDAP", [389, 636], "Lightweight Directory Access Protocol"),
    "MYSQL": ServiceProfile("MYSQL", "DATABASE", [3306], "MySQL Database"),
    "POSTGRESQL": ServiceProfile("POSTGRESQL", "DATABASE", [5432], "PostgreSQL Database"),
    "REDIS": ServiceProfile("REDIS", "DATABASE", [6379], "Redis Datastore"),
    "MONGODB": ServiceProfile("MONGODB", "DATABASE", [27017], "MongoDB Database"),
    "GENERIC": ServiceProfile("GENERIC", "GENERIC", [], "Generic Network Service"),
}


class TechnologyClassifier:
    """Classifies target technologies and frameworks from banners, headers, CPEs, and endpoints."""

    TECH_PATTERNS: Dict[str, List[str]] = {
        "WORDPRESS": [
            r"\bwordpress\b",
            r"/wp-content/",
            r"/wp-includes/",
            r"wp-json",
            r"cpe:2.3:a:wordpress:wordpress",
        ],
        "TOMCAT": [
            r"\btomcat\b",
            r"apache-coyote",
            r"cpe:2.3:a:apache:tomcat",
            r"cpe:2.3:a:apache_software_foundation:tomcat",
            r"apache jserv",
            r"ajp13",
        ],
        "APACHE": [
            r"\bapache\b",
            r"apache httpd",
            r"apache\s*/\s*[0-9]",
            r"cpe:2.3:a:apache:http_server",
        ],
        "NGINX": [
            r"\bnginx\b",
            r"cpe:2.3:a:nginx:nginx",
            r"cpe:2.3:a:f5:nginx",
        ],
        "PHP": [
            r"\bphp\b",
            r"php/\d",
            r"phpsessid",
            r"x-powered-by:.*php",
            r"cpe:2.3:a:php:php",
        ],
        "JOOMLA": [
            r"\bjoomla\b",
            r"joomla!",
            r"/media/jui/",
            r"cpe:2.3:a:joomla:joomla\!",
        ],
        "DRUPAL": [
            r"\bdrupal\b",
            r"x-generator:.*drupal",
            r"cpe:2.3:a:drupal:drupal",
        ],
        "SPRING": [
            r"\bspring\b",
            r"spring-boot",
            r"whitelabel error page",
            r"x-application-context",
        ],
        "LARAVEL": [
            r"\blaravel\b",
            r"laravel_session",
            r"x-powered-by:.*laravel",
        ],
        "DJANGO": [
            r"\bdjango\b",
            r"csrftoken",
            r"__admin__",
        ],
        "ASPNET": [
            r"\basp\.net\b",
            r"aspnet",
            r"x-aspnet-version",
            r"x-powered-by:.*aspnet",
            r"__viewstate",
        ],
        "NODE": [
            r"\bnode\.js\b",
            r"\bexpress\b",
            r"x-powered-by:.*express",
        ],
    }

    @classmethod
    def classify_target(
        cls,
        target: Target,
        host: Optional[Host] = None,
        endpoints: Optional[List[WebEndpoint]] = None,
    ) -> Set[str]:
        """Identifies technology keys matching the target evidence."""
        detected: Set[str] = set()
        corpus_parts: List[str] = []

        hosts = [host] if host else list(target.hosts.values())
        for h in hosts:
            for port in h.ports:
                if port.service:
                    if port.service.name:
                        corpus_parts.append(port.service.name)
                    if port.service.product:
                        corpus_parts.append(port.service.product)
                    if port.service.version:
                        corpus_parts.append(port.service.version)
                    if port.service.cpe:
                        corpus_parts.append(port.service.cpe)
                    if getattr(port.service, "extra_info", ""):
                        corpus_parts.append(port.service.extra_info)

            eps = endpoints if endpoints is not None else h.web_endpoints
            for ep in eps:
                corpus_parts.append(ep.url)
                if getattr(ep, "path", None):
                    corpus_parts.append(ep.path)
                if getattr(ep, "body_preview", None):
                    corpus_parts.append(ep.body_preview[:1000])
                if getattr(ep, "headers", None) and isinstance(ep.headers, dict):
                    for header_k, header_v in ep.headers.items():
                        corpus_parts.append(f"{header_k}: {header_v}")
                if getattr(ep, "technologies", None):
                    for tech in ep.technologies:
                        corpus_parts.append(tech.name)
                        if getattr(tech, "version", None):
                            corpus_parts.append(tech.version)
                        for val in getattr(tech, "detected_values", []):
                            corpus_parts.append(val)

        full_corpus = " \n ".join(corpus_parts).lower()

        for tech_name, patterns in cls.TECH_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, full_corpus, re.IGNORECASE):
                    detected.add(tech_name)
                    break

        return detected


class DiscoveryProfileComposer:
    """Fuses the common discovery baseline with all automatically identified technology profiles.

    Guarantees:
    - The Common baseline is ALWAYS preserved.
    - Application-specific profiles are ADDED, never substituted for the baseline.
    - All candidates are normalized, deduplicated, and sorted deterministically.
    - Trailing slashes and file extensions are strictly preserved.
    - High-signal paths (e.g. /secret/, /backup/, /admin/, /robots.txt) are retained.
    """

    def __init__(self, wordlist_dir: Optional[str] = None):
        if wordlist_dir:
            self.wordlist_dir = wordlist_dir
        else:
            self.wordlist_dir = load_config().wordlist_dir

    def _read_wordlist_file(self, rel_path: str) -> List[str]:
        path = os.path.join(self.wordlist_dir, rel_path)
        if not os.path.exists(path):
            return []
        words = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    words.append(line)
        except OSError:
            pass
        return words

    @staticmethod
    def normalize_candidate(raw: str) -> Optional[str]:
        """Normalizes path candidate while strictly preserving trailing slashes and file extensions."""
        candidate = raw.strip()
        if not candidate or candidate.startswith("#"):
            return None

        # Remove leading exclamation markers used in old lists
        if candidate.startswith("!"):
            candidate = candidate.lstrip("!").strip()

        # Remove leading slashes (/secret/ -> secret/)
        candidate = candidate.lstrip("/")
        if not candidate:
            return None

        # Collapse multiple internal slashes (e.g. api//v1/ -> api/v1/)
        candidate = re.sub(r"/+", "/", candidate)
        return candidate

    def compose_profile(
        self,
        depth: str = "COMMON",
        technologies: Optional[Set[str]] = None,
        custom_candidates: Optional[List[str]] = None,
    ) -> Tuple[List[str], List[str], List[str]]:
        """Composes composite wordlist, active technology profile names, and extension list.

        Returns: (candidate_paths, active_technology_names, extensions)
        """
        depth_key = (depth or "COMMON").upper()
        base_profile = DISCOVERY_PROFILES.get(depth_key, DISCOVERY_PROFILES["COMMON"])

        # 1. Start with Common Baseline wordlists (ALWAYS PRESERVED)
        raw_words: List[str] = []
        raw_words.extend(self._read_wordlist_file(base_profile.default_wordlist))
        for cat in base_profile.category_wordlists:
            raw_words.extend(self._read_wordlist_file(cat))

        extensions_set: Set[str] = set(base_profile.extensions)
        active_techs: List[str] = []

        # 2. Add Technology-Specific Profiles
        if technologies:
            for tech in sorted(technologies):
                tech_key = tech.upper()
                if tech_key in TECHNOLOGY_PROFILES:
                    t_prof = TECHNOLOGY_PROFILES[tech_key]
                    active_techs.append(tech_key)
                    raw_words.extend(self._read_wordlist_file(t_prof.wordlist_file))
                    extensions_set.update(t_prof.extensions)

        # 3. Add Custom / Injected Candidates
        if custom_candidates:
            raw_words.extend(custom_candidates)

        # 4. Strict Normalization, Trailing-Slash Preservation, and Deterministic Deduplication
        seen_keys: Set[str] = set()
        final_candidates: List[str] = []

        for item in raw_words:
            norm = self.normalize_candidate(item)
            if not norm:
                continue

            # Preserves distinction between 'secret/' (directory) and 'secret' (file)
            dedup_key = norm.lower()
            if dedup_key not in seen_keys:
                seen_keys.add(dedup_key)
                final_candidates.append(norm)

        # 5. Order extensions deterministically
        priority_exts = [".php", ".jsp", ".aspx", ".html", ".json", ".txt", ".xml", ".js", ".bak", ".env", ".log", ".sql", ".zip"]
        ordered_exts = [e for e in priority_exts if e in extensions_set]
        ordered_exts.extend(sorted(e for e in extensions_set if e not in priority_exts))

        return final_candidates, active_techs, ordered_exts

    def write_composite_wordlist(
        self,
        output_dir: str,
        depth: str = "COMMON",
        technologies: Optional[Set[str]] = None,
        custom_candidates: Optional[List[str]] = None,
    ) -> Tuple[str, List[str], List[str]]:
        """Writes the composed wordlist to the session output directory."""
        candidates, active_techs, exts = self.compose_profile(
            depth=depth,
            technologies=technologies,
            custom_candidates=custom_candidates,
        )

        tech_suffix = "_".join(t.lower() for t in active_techs) if active_techs else "base"
        filename = f"sentinelrecon_{depth.lower()}_{tech_suffix}_wordlist.txt"
        file_path = os.path.join(output_dir, filename)

        os.makedirs(output_dir, exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            for word in candidates:
                f.write(f"{word}\n")

        return file_path, active_techs, exts


# Aliases for architectural completeness
DiscoveryPlanner = DiscoveryProfileComposer
DiscoveryExecutor = DiscoveryProfileComposer


def get_discovery_profile(name: Optional[str]) -> DiscoveryProfile:
    if not name:
        return DISCOVERY_PROFILES["COMMON"]
    return DISCOVERY_PROFILES.get(name.upper(), DISCOVERY_PROFILES["COMMON"])
