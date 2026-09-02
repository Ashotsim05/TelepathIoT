from __future__ import annotations

from typing import Any

from telepathiot.mqtt.paho_util import subscribe_collect
from telepathiot.scope import AuthorizedTarget
from telepathiot.secrets import FindingsStore, looks_secret
from telepathiot.session import Session

HONEYPOT_HINTS = ("admin/token", "admin/password", "token", "secret")
WILDCARDS = ["#", "+/+", "sensors/#", "admin/#"]


def _flag_topic(topic: str) -> bool:
    t = topic.lower()
    return any(h in t for h in HONEYPOT_HINTS)


def run_topics(
    target: AuthorizedTarget,
    session: Session,
    findings: FindingsStore,
    *,
    username: str | None = None,
    password: str | None = None,
    listen_s: float = 4.0,
    use_tls: bool | None = None,
) -> dict[str, Any]:
    tls = use_tls if use_tls is not None else target.protocol == "mqtts"
    session.log_action("topics", "start", target=target.key, detail={"label": target.label})

    collected = subscribe_collect(
        target.host,
        target.port,
        WILDCARDS,
        session,
        username=username,
        password=password,
        listen_s=listen_s,
        use_tls=tls,
    )

    denied = False
    if collected.rc not in (None, 0) or (
        collected.suback_codes and all(c >= 128 for c in collected.suback_codes)
    ):
        denied = True

    if collected.error:
        denied = True

    topics_seen: dict[str, dict[str, Any]] = {}
    honeypots = []
    for msg in collected.messages:
        entry = topics_seen.setdefault(
            msg.topic,
            {"retain": msg.retain, "qos": msg.qos, "count": 0, "secretish": False},
        )
        entry["count"] += 1
        entry["retain"] = entry["retain"] or msg.retain
        if looks_secret(msg.topic, msg.payload) or _flag_topic(msg.topic):
            entry["secretish"] = True
            handle = findings.record(
                kind="retained_or_live_payload",
                source=f"{target.key}:{msg.topic}",
                secret=msg.payload,
                extra={"retain": msg.retain},
            )
            honeypots.append({"topic": msg.topic, "retain": msg.retain, "secret_redacted": handle})
            session.add_finding(
                {
                    "module": "topics",
                    "severity": "high",
                    "title": "Sensitive topic/payload observed",
                    "target": target.key,
                    "topic": msg.topic,
                    "retain": msg.retain,
                    "secret_redacted": handle,
                }
            )

    result = {
        "label": target.label,
        "target": target.key,
        "connected": collected.connected,
        "denied": denied and not collected.messages,
        "timed_out": collected.timed_out,
        "suback_codes": collected.suback_codes,
        "error": collected.error,
        "topic_count": len(topics_seen),
        "topics": topics_seen,
        "sensitive": honeypots,
    }

    if result["denied"]:
        session.add_finding(
            {
                "module": "topics",
                "severity": "info",
                "title": "Wildcard subscribe denied (clean)",
                "target": target.key,
                "suback_codes": collected.suback_codes,
                "connect_rc": collected.rc,
            }
        )
        session.log_action(
            "topics",
            "wildcard_denied",
            target=target.key,
            detail={"suback_codes": collected.suback_codes, "rc": collected.rc},
            ok=True,
        )

    session.set_module("topics", result)
    session.log_action("topics", "done", target=target.key, detail={"topic_count": len(topics_seen), "denied": result["denied"]})
    return result
