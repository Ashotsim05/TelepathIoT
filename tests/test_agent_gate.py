from __future__ import annotations

from pathlib import Path

import pytest

from telepathiot.agent_tools import AgentContext, HumanGateRequired, bruteforce
from telepathiot.scope import load_scope
from telepathiot.secrets import FindingsStore
from telepathiot.session import Session


def test_bruteforce_requires_human_gate(tmp_path: Path) -> None:
    scope_path = tmp_path / "scope.json"
    scope_path.write_text(
        '{"authorized_targets":[{"label":"x","host":"127.0.0.1","port":1883}]}',
        encoding="utf-8",
    )
    ctx = AgentContext(
        scope=load_scope(scope_path),
        session=Session(tmp_path),
        findings=FindingsStore(tmp_path),
        confirmed_intrusive=set(),
    )
    with pytest.raises(HumanGateRequired):
        bruteforce(ctx, "x", "users.txt", "pass.txt", human_confirmed=False)
