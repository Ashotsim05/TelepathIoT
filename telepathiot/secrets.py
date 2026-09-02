from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from telepathiot.constants import FINDINGS_FILENAME

_SECRET_KEYS = frozenset(
    {"password", "passwd", "token", "secret", "credential", "api_key", "apikey"}
)
_TOKENISH = re.compile(r"(?i)(password|passwd|token|secret|api[_-]?key)\s*[:=]\s*\S+")


def redact_value(value: str) -> str:
    if not value:
        return ""
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:8]
    return f"[REDACTED:{digest}]"


def looks_secret(topic: str, payload: str) -> bool:
    blob = f"{topic} {payload}".lower()
    if any(k in blob for k in ("token", "password", "passwd", "secret", "api_key", "apikey")):
        return True
    return bool(_TOKENISH.search(payload))


class FindingsStore:
    """Gitignored local store for extracted secrets. Never print full values."""

    def __init__(self, root: Path) -> None:
        self.path = root / FINDINGS_FILENAME
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self._write({"secrets": []})

    def _read(self) -> dict[str, Any]:
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _write(self, data: dict[str, Any]) -> None:
        self.path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    def record(
        self,
        *,
        kind: str,
        source: str,
        username: str | None = None,
        secret: str,
        extra: dict[str, Any] | None = None,
    ) -> str:
        handle = redact_value(secret)
        data = self._read()
        entry = {
            "kind": kind,
            "source": source,
            "username": username,
            "secret_redacted": handle,
            "secret": secret,
            "extra": extra or {},
        }
        data.setdefault("secrets", []).append(entry)
        self._write(data)
        return handle

    def public_summary(self) -> list[dict[str, Any]]:
        data = self._read()
        out = []
        for item in data.get("secrets") or []:
            out.append(
                {
                    "kind": item.get("kind"),
                    "source": item.get("source"),
                    "username": item.get("username"),
                    "secret_redacted": item.get("secret_redacted"),
                }
            )
        return out
