import os
from dataclasses import dataclass
from typing import Dict, Any


@dataclass
class AppConfig:
    timeout: int = 300
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    session_dir: str = os.path.expanduser("~/.sentinelrecon/sessions")
    wordlist_dir: str = os.path.join(os.path.dirname(os.path.dirname(__file__)), "wordlists")
    max_threads: int = 10
    default_ports: str = "top-1000"


def load_config() -> AppConfig:
    config = AppConfig()
    env_timeout = os.getenv("SENTINELRECON_TIMEOUT") or os.getenv("RECONFORGE_TIMEOUT")
    if env_timeout:
        try:
            config.timeout = int(env_timeout)
        except ValueError:
            pass

    env_ua = os.getenv("SENTINELRECON_USER_AGENT") or os.getenv("RECONFORGE_USER_AGENT")
    if env_ua:
        config.user_agent = env_ua

    env_session = os.getenv("SENTINELRECON_SESSION_DIR") or os.getenv("RECONFORGE_SESSION_DIR")
    if env_session:
        config.session_dir = os.path.expanduser(env_session)
    elif not os.path.exists(config.session_dir) and os.path.exists(os.path.expanduser("~/.reconforge/sessions")):
        # Compatibility fallback if older session directory exists
        config.session_dir = os.path.expanduser("~/.sentinelrecon/sessions")

    env_wordlist = os.getenv("SENTINELRECON_WORDLIST_DIR") or os.getenv("RECONFORGE_WORDLIST_DIR")
    if env_wordlist:
        config.wordlist_dir = os.path.expanduser(env_wordlist)

    env_threads = os.getenv("SENTINELRECON_THREADS") or os.getenv("RECONFORGE_THREADS")
    if env_threads:
        try:
            config.max_threads = int(env_threads)
        except ValueError:
            pass

    return config
