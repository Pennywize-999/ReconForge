import os
import ast
from dataclasses import dataclass, field
from typing import List

try:
    import tomllib
except ImportError:
    tomllib = None

@dataclass
class ReconConfig:
    timeout: int = 300
    gobuster_threads: int = 10
    default_wordlists: List[str] = field(default_factory=lambda: [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    ])
    output_directory: str = "sessions"
    low_impact_delay: int = 2
    max_response_size: int = 5242880 # 5 MB

def load_config() -> ReconConfig:
    config = ReconConfig()

    paths = [
        os.path.join(os.getcwd(), "reconforge.toml"),
        os.path.expanduser("~/.config/reconforge/config.toml")
    ]

    for path in paths:
        if os.path.exists(path):
            _parse_toml(path, config)
            break

    return config

def _parse_toml(path: str, config: ReconConfig):
    if tomllib:
        with open(path, "rb") as f:
            data = tomllib.load(f)
            _apply_dict(data, config)
        return

    # Naive fallback for Python < 3.11 without tomli
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("["):
                continue
            if "=" in line:
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip()
                try:
                    # use ast.literal_eval for simple ints, lists, strings
                    parsed_val = ast.literal_eval(val)
                    if hasattr(config, key):
                        setattr(config, key, parsed_val)
                except Exception:
                    pass

def _apply_dict(data: dict, config: ReconConfig):
    for k, v in data.items():
        if hasattr(config, k):
            setattr(config, k, v)
        elif isinstance(v, dict):
            _apply_dict(v, config) # flatten
