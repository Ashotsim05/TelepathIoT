from __future__ import annotations

from pathlib import Path

from telepathiot.mqtt.transport import random_client_id
from telepathiot.rate_limit import RateLimiter
from telepathiot.session import Session


def test_random_client_ids_differ() -> None:
    ids = {random_client_id() for _ in range(20)}
    assert len(ids) == 20
    assert all(i.startswith("tpiot-") for i in ids)


def test_session_flush(tmp_path: Path) -> None:
    s = Session(tmp_path, session_id="abc123")
    s.log_action("test", "ping", target="127.0.0.1:1883")
    s.mark_aborted()
    data = s.path.read_text(encoding="utf-8")
    assert "ping" in data
    assert '"aborted": true' in data
    assert s.action_log.exists()


def test_connection_cap(tmp_path: Path) -> None:
    s = Session(tmp_path)
    s.set_connection_cap(2)
    s.note_connection()
    s.note_connection()
    try:
        s.note_connection()
        assert False, "should cap"
    except RuntimeError:
        pass


def test_rate_limiter_delay() -> None:
    import time

    rl = RateLimiter(50)
    t0 = time.monotonic()
    rl.wait()
    rl.wait()
    elapsed = time.monotonic() - t0
    assert elapsed >= 0.04
