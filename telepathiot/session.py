from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from telepathiot.constants import ACTION_LOG_NAME, SESSION_DIR


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Session:
    """Structured session.json plus a line-oriented action log (evidence trail)."""

    def __init__(self, root: Path, session_id: str | None = None) -> None:
        self.root = Path(root)
        self.dir = self.root / SESSION_DIR
        self.dir.mkdir(parents=True, exist_ok=True)
        self.session_id = session_id or uuid.uuid4().hex[:12]
        self.path = self.dir / f"{self.session_id}.session.json"
        self.action_log = self.dir / f"{self.session_id}.{ACTION_LOG_NAME}"
        self._lock = threading.Lock()
        self._connections_used = 0
        self._connection_cap = 10_000
        self.data: dict[str, Any] = {
            "session_id": self.session_id,
            "started_at": _utc_now(),
            "updated_at": _utc_now(),
            "aborted": False,
            "connection_attempts": 0,
            "actions": [],
            "findings": [],
            "modules": {},
        }
        self.flush()

    def set_connection_cap(self, cap: int) -> None:
        self._connection_cap = cap

    def note_connection(self) -> None:
        with self._lock:
            self._connections_used += 1
            self.data["connection_attempts"] = self._connections_used
            if self._connections_used > self._connection_cap:
                raise RuntimeError(
                    f"Session connection cap reached ({self._connection_cap}). "
                    "Refusing further connects."
                )

    def log_action(
        self,
        module: str,
        action: str,
        *,
        target: str | None = None,
        detail: dict[str, Any] | None = None,
        ok: bool = True,
    ) -> None:
        rec = {
            "ts": _utc_now(),
            "module": module,
            "action": action,
            "target": target,
            "ok": ok,
            "detail": detail or {},
        }
        line = json.dumps(rec, ensure_ascii=True)
        with self._lock:
            self.data["actions"].append(rec)
            self.data["updated_at"] = rec["ts"]
            with self.action_log.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            self._write_unlocked()

    def add_finding(self, finding: dict[str, Any]) -> None:
        finding = dict(finding)
        finding.setdefault("ts", _utc_now())
        finding.setdefault("id", uuid.uuid4().hex[:10])
        with self._lock:
            self.data["findings"].append(finding)
            self._write_unlocked()

    def set_module(self, name: str, result: dict[str, Any]) -> None:
        with self._lock:
            self.data["modules"][name] = result
            self.data["updated_at"] = _utc_now()
            self._write_unlocked()

    def mark_aborted(self) -> None:
        with self._lock:
            self.data["aborted"] = True
            self.data["updated_at"] = _utc_now()
            self._write_unlocked()

    def flush(self) -> None:
        with self._lock:
            self._write_unlocked()

    def _write_unlocked(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=2) + "\n", encoding="utf-8")
        tmp.replace(self.path)
