from __future__ import annotations

import ipaddress
import json
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class ScopeError(Exception):
    """Target is not on the authorized allowlist."""


@dataclass(frozen=True)
class AuthorizedTarget:
    label: str
    host: str
    port: int
    protocol: str = "mqtt"
    notes: str = ""

    @property
    def key(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass
class Scope:
    path: Path
    require_isolated_network: bool
    docker_network_name: str
    session_connection_cap: int
    default_rate_limit_ms: int
    targets: list[AuthorizedTarget] = field(default_factory=list)

    def by_label(self, label: str) -> AuthorizedTarget | None:
        wanted = label.strip().lower()
        for t in self.targets:
            if t.label.lower() == wanted:
                return t
        return None

    def find(self, host: str, port: int) -> AuthorizedTarget | None:
        host_n = canonicalize_host(host)
        for t in self.targets:
            if canonicalize_host(t.host) == host_n and t.port == port:
                return t
        return None

    def require(self, host: str, port: int) -> AuthorizedTarget:
        found = self.find(host, port)
        if found is None:
            raise ScopeError(
                f"Refusing contact to {host}:{port} — not in scope.json allowlist. "
                "Add the target explicitly after human authorization."
            )
        return found

    def require_label_or_host(self, spec: str, port: int | None = None) -> AuthorizedTarget:
        labeled = self.by_label(spec)
        if labeled is not None:
            return labeled
        if port is None:
            raise ScopeError(
                f"Unknown label {spec!r} and no --port given. Use a scope label or host+port."
            )
        return self.require(spec, port)


def canonicalize_host(host: str) -> str:
    h = host.strip().lower()
    if h in {"localhost", "::1"}:
        return "127.0.0.1"
    try:
        ip = ipaddress.ip_address(h)
        if ip.version == 6 and ip.ipv4_mapped:
            return str(ip.ipv4_mapped)
        return str(ip)
    except ValueError:
        try:
            return socket.gethostbyname(h)
        except OSError:
            return h


def load_scope(path: str | Path) -> Scope:
    p = Path(path)
    if not p.exists():
        raise ScopeError(
            f"Scope file not found: {p}. Copy scope.example.json to scope.json and edit it."
        )
    raw: dict[str, Any] = json.loads(p.read_text(encoding="utf-8"))
    targets = []
    for item in raw.get("authorized_targets") or []:
        targets.append(
            AuthorizedTarget(
                label=str(item["label"]),
                host=str(item["host"]),
                port=int(item["port"]),
                protocol=str(item.get("protocol") or "mqtt"),
                notes=str(item.get("notes") or ""),
            )
        )
    if not targets:
        raise ScopeError("scope.json has no authorized_targets.")
    return Scope(
        path=p,
        require_isolated_network=bool(raw.get("require_isolated_network", True)),
        docker_network_name=str(raw.get("docker_network_name") or "telepathiot-lab"),
        session_connection_cap=int(raw.get("session_connection_cap") or 500),
        default_rate_limit_ms=int(raw.get("default_rate_limit_ms") or 200),
        targets=targets,
    )
