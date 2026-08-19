import os
import pickle
import json
from datetime import datetime
from reconforge.core.models import ScanSession, Target, ModelEncoder

class SessionManager:
    def __init__(self, output_dir: str = None):
        self.base_dir = output_dir or os.path.normpath(os.path.expanduser("~/.reconforge/sessions"))
        os.makedirs(self.base_dir, exist_ok=True)
        self.current_link = os.path.join(self.base_dir, "current")

    def create_session(self, target: Target) -> ScanSession:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        session_id = f"session_{timestamp}"

        session_dir = os.path.join(self.base_dir, session_id)
        os.makedirs(session_dir, exist_ok=True)

        session = ScanSession(
            id=session_id,
            timestamp=timestamp,
            target=target
        )
        self.save_session(session)
        self.set_current(session_id)
        return session

    def get_session_dir(self, session_id: str) -> str:
        return os.path.join(self.base_dir, session_id)

    def save_session(self, session: ScanSession):
        session_dir = self.get_session_dir(session.id)
        os.makedirs(session_dir, exist_ok=True)

        session_path = os.path.join(session_dir, "target.json")
        with open(session_path, "w", encoding="utf-8") as f:
            json.dump(session, f, cls=ModelEncoder, indent=2)

    def load_session(self, session_id: str) -> ScanSession:
        session_dir = self.get_session_dir(session_id)

        json_path = os.path.join(session_dir, "target.json")
        if os.path.exists(json_path):
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return ScanSession.from_dict(data)

        old_json_path = os.path.join(self.base_dir, f"{session_id}.json")
        if os.path.exists(old_json_path):
            with open(old_json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return ScanSession.from_dict(data)

        pkl_path = os.path.join(self.base_dir, f"{session_id}.pkl")
        if os.path.exists(pkl_path):
            with open(pkl_path, "rb") as f:
                return pickle.load(f)

        raise ValueError(f"Session {session_id} not found.")

    def set_current(self, session_id: str):
        with open(self.current_link, "w") as f:
            f.write(session_id)

    def get_current(self) -> ScanSession:
        if not os.path.exists(self.current_link):
            raise ValueError("No current session found.")
        with open(self.current_link, "r") as f:
            session_id = f.read().strip()
        return self.load_session(session_id)

    def list_sessions(self) -> list:
        sessions = set()
        for item in os.listdir(self.base_dir):
            path = os.path.join(self.base_dir, item)
            if os.path.isdir(path) and item.startswith("session_"):
                sessions.add(item)
            elif item.endswith(".json") and item != "current":
                session_id = item.replace(".json", "")
                sessions.add(session_id)
            elif item.endswith(".pkl") and item != "current":
                session_id = item.replace(".pkl", "")
                sessions.add(session_id)
        return sorted(list(sessions), reverse=True)
