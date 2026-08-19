import os
import pickle
import json
from datetime import datetime
from reconforge.core.models import ScanSession, Target, ModelEncoder

class SessionManager:
    def __init__(self):
        self.base_dir = os.path.expanduser("~/.reconforge/sessions")
        os.makedirs(self.base_dir, exist_ok=True)
        self.current_link = os.path.join(self.base_dir, "current")

    def create_session(self, target: Target) -> ScanSession:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        session_id = f"session_{timestamp}"

        session = ScanSession(
            id=session_id,
            timestamp=timestamp,
            target=target
        )
        self.save_session(session)
        self.set_current(session_id)
        return session

    def save_session(self, session: ScanSession):
        session_path = os.path.join(self.base_dir, f"{session.id}.json")
        with open(session_path, "w") as f:
            json.dump(session, f, cls=ModelEncoder, indent=2)

    def load_session(self, session_id: str) -> ScanSession:
        # Check JSON first
        json_path = os.path.join(self.base_dir, f"{session_id}.json")
        if os.path.exists(json_path):
            with open(json_path, "r") as f:
                data = json.load(f)
                return ScanSession.from_dict(data)

        # Fallback to Pickle for v0.1.0 compatibility
        pkl_path = os.path.join(self.base_dir, f"{session_id}.pkl")
        if os.path.exists(pkl_path):
            with open(pkl_path, "rb") as f:
                return pickle.load(f)

        raise ValueError(f"Session {session_id} not found.")

    def set_current(self, session_id: str):
        if not os.path.exists(os.path.join(self.base_dir, f"{session_id}.json")) and not os.path.exists(os.path.join(self.base_dir, f"{session_id}.pkl")):
            raise ValueError(f"Session {session_id} not found.")

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
        for file in os.listdir(self.base_dir):
            if file.endswith(".json") or file.endswith(".pkl"):
                session_id = file.replace(".json", "").replace(".pkl", "")
                sessions.add(session_id)
        return sorted(list(sessions), reverse=True)
