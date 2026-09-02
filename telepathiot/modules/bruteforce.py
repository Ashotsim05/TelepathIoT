from __future__ import annotations

from pathlib import Path
from typing import Any

from telepathiot.constants import MQTT311_PROTOCOL_LEVEL, MQTT50_PROTOCOL_LEVEL
from telepathiot.mqtt.transport import raw_connect
from telepathiot.rate_limit import RateLimiter
from telepathiot.scope import AuthorizedTarget
from telepathiot.secrets import FindingsStore
from telepathiot.session import Session


def _load_lines(path: Path) -> list[str]:
    lines = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if s and not s.startswith("#"):
            lines.append(s)
    return lines


def run_bruteforce(
    target: AuthorizedTarget,
    session: Session,
    findings: FindingsStore,
    *,
    users_file: Path,
    passwords_file: Path,
    rate_limit_ms: int,
    recon_hint: dict[str, Any] | None = None,
    use_tls: bool | None = None,
    protocol: str = "mqtt311",
) -> dict[str, Any]:
    tls = use_tls if use_tls is not None else target.protocol == "mqtts"
    session.log_action(
        "bruteforce",
        "start",
        target=target.key,
        detail={"rate_limit_ms": rate_limit_ms, "label": target.label},
    )

    if recon_hint and recon_hint.get("enhanced_auth"):
        result = {
            "skipped": True,
            "reason": "enhanced_auth_out_of_scope",
            "note": (
                "MQTT 5 AUTH / enhanced authentication detected during recon. "
                "CONNECT username/password bruteforce would miss this mechanism. Not a negative."
            ),
        }
        session.set_module("bruteforce", result)
        session.add_finding(
            {
                "module": "bruteforce",
                "severity": "info",
                "title": "Bruteforce skipped — enhanced AUTH in use",
                "target": target.key,
            }
        )
        return result

    users = _load_lines(users_file)
    passwords = _load_lines(passwords_file)
    limiter = RateLimiter(rate_limit_ms)
    level = MQTT50_PROTOCOL_LEVEL if protocol == "mqtt5" else MQTT311_PROTOCOL_LEVEL
    attempts = 0
    success: dict[str, Any] | None = None

    for user in users:
        if success:
            break
        for passwd in passwords:
            limiter.wait()
            attempts += 1
            try:
                connack = raw_connect(
                    target.host,
                    target.port,
                    protocol_level=level,
                    session=session,
                    username=user,
                    password=passwd,
                    use_tls=tls,
                )
            except OSError as exc:
                session.log_action(
                    "bruteforce",
                    "attempt_error",
                    target=target.key,
                    detail={"username": user, "error": str(exc)},
                    ok=False,
                )
                continue
            accepted = connack.accepted
            session.log_action(
                "bruteforce",
                "attempt",
                target=target.key,
                detail={
                    "username": user,
                    "attempt": attempts,
                    "accepted": accepted,
                    "reason_name": connack.reason_name,
                },
            )
            if connack.enhanced_auth or connack.packet_type == "AUTH":
                result = {
                    "skipped": True,
                    "reason": "enhanced_auth_mid_run",
                    "attempts": attempts,
                }
                session.set_module("bruteforce", result)
                return result
            if accepted:
                handle = findings.record(
                    kind="bruteforce_credentials",
                    source=target.key,
                    username=user,
                    secret=passwd,
                )
                success = {"username": user, "secret_redacted": handle}
                session.add_finding(
                    {
                        "module": "bruteforce",
                        "severity": "critical",
                        "title": "Valid credentials found",
                        "target": target.key,
                        "username": user,
                        "secret_redacted": handle,
                    }
                )
                session.log_action(
                    "bruteforce",
                    "success_stop",
                    target=target.key,
                    detail={"username": user, "attempts": attempts},
                )
                break

    result = {
        "skipped": False,
        "target": target.key,
        "attempts": attempts,
        "rate_limit_ms": rate_limit_ms,
        "success": success,
        "stopped_after_success": bool(success),
        "user_count": len(users),
        "password_count": len(passwords),
    }
    session.set_module("bruteforce", result)
    session.log_action("bruteforce", "done", target=target.key, detail={"attempts": attempts, "success": bool(success)})
    return result
