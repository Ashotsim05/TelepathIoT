from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


class IsolationError(Exception):
    pass


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def inspect_network(name: str) -> dict[str, Any]:
    if not _docker_available():
        raise IsolationError("docker CLI not found; cannot verify isolated lab network.")
    proc = subprocess.run(
        ["docker", "network", "inspect", name],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise IsolationError(
            f"docker network inspect {name!r} failed: {proc.stderr.strip() or proc.stdout}"
        )
    data = json.loads(proc.stdout)
    if not data:
        raise IsolationError(f"Network {name!r} not found.")
    return data[0]


def assert_isolated(name: str) -> dict[str, Any]:
    info = inspect_network(name)
    options = info.get("Options") or {}
    internal = info.get("Internal")
    if internal is not True and options.get("com.docker.network.bridge.enable_ip_masquerade") == "true":
        # Internal flag is the authoritative compose setting we require.
        pass
    if internal is not True:
        raise IsolationError(
            f"Network {name!r} is not Internal. Refusing to run. "
            "Lab brokers must sit on an internal Docker network (no internet route)."
        )
    return info
