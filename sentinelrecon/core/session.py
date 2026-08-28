import json
import os
import time
from typing import List, Optional
from sentinelrecon.core.config import load_config
from sentinelrecon.core.models import ModelEncoder, ScanSession, Target


class SessionManager:
    def __init__(self, session_dir: Optional[str] = None):
        if session_dir:
            self.session_dir = session_dir
        else:
            config = load_config()
            self.session_dir = config.session_dir
        os.makedirs(self.session_dir, exist_ok=True)

    def create_session(self, target: Target) -> ScanSession:
        timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
        session_id = f"session_{timestamp}"
        session = ScanSession(id=session_id, timestamp=timestamp, target=target)
        self.save_session(session)
        return session

    def save_session(self, session: ScanSession):
        s_dir = os.path.join(self.session_dir, session.id)
        os.makedirs(s_dir, exist_ok=True)
        session_file = os.path.join(s_dir, "session.json")
        with open(session_file, "w", encoding="utf-8") as f:
            json.dump(session, f, cls=ModelEncoder, indent=2)

    def _all_search_dirs(self) -> List[str]:
        dirs = [self.session_dir]
        legacy_dir = os.path.expanduser("~/.reconforge/sessions")
        if os.path.exists(legacy_dir) and legacy_dir not in dirs:
            dirs.append(legacy_dir)
        return dirs

    def get_session(self, session_id: str) -> Optional[ScanSession]:
        for base_dir in self._all_search_dirs():
            session_file = os.path.join(base_dir, session_id, "session.json")
            if os.path.exists(session_file):
                with open(session_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return ScanSession.from_dict(data)
        return None

    def list_sessions(self) -> List[str]:
        sessions = set()
        for base_dir in self._all_search_dirs():
            if os.path.exists(base_dir):
                for d in os.listdir(base_dir):
                    if os.path.isdir(os.path.join(base_dir, d)) and os.path.exists(os.path.join(base_dir, d, "session.json")):
                        sessions.add(d)
        return sorted(list(sessions), reverse=True)

    def get_latest_session(self) -> Optional[ScanSession]:
        sessions = self.list_sessions()
        if sessions:
            return self.get_session(sessions[0])
        return None

    def get_session_dir(self, session_id: str) -> str:
        for base_dir in self._all_search_dirs():
            p = os.path.join(base_dir, session_id)
            if os.path.exists(p):
                return p
        return os.path.join(self.session_dir, session_id)

    load_session = get_session
    get_current = get_latest_session
