from __future__ import annotations

import time
from typing import Any

from telepathiot.mqtt.paho_util import publish_once, subscribe_collect
from telepathiot.rate_limit import RateLimiter
from telepathiot.scope import AuthorizedTarget
from telepathiot.session import Session

DEFAULT_PROBE_TOPICS = [
    "sensors/device1/temp",
    "sensors/other/temp",
    "admin/token",
    "admin/#",
    "#",
    "$SYS/broker/version",
]


def run_acl(
    target: AuthorizedTarget,
    session: Session,
    *,
    username: str,
    password: str,
    topics: list[str] | None = None,
    rate_limit_ms: int,
    timeout_s: float = 5.0,
    use_tls: bool | None = None,
) -> dict[str, Any]:
    tls = use_tls if use_tls is not None else target.protocol == "mqtts"
    topics = topics or DEFAULT_PROBE_TOPICS
    limiter = RateLimiter(rate_limit_ms)
    session.log_action(
        "acl",
        "start",
        target=target.key,
        detail={"username": username, "topic_count": len(topics)},
    )

    mapping: list[dict[str, Any]] = []
    for topic in topics:
        limiter.wait()
        sub = subscribe_collect(
            target.host,
            target.port,
            [topic],
            session,
            username=username,
            password=password,
            listen_s=0.4,
            use_tls=tls,
            timeout=timeout_s,
        )
        sub_status = "unknown"
        if sub.error:
            sub_status = "error"
        elif sub.timed_out and sub.rc is None:
            sub_status = "timeout_not_denial"
        elif sub.rc not in (None, 0):
            sub_status = "connect_denied"
        elif sub.suback_codes and all(c >= 128 for c in sub.suback_codes):
            sub_status = "subscribe_denied"
        elif sub.connected:
            sub_status = "subscribe_allowed"

        limiter.wait()
        marker = f"telepathiot-acl-probe-{int(time.time())}"
        pub = publish_once(
            target.host,
            target.port,
            topic,
            marker,
            session,
            username=username,
            password=password,
            qos=0,
            retain=False,
            use_tls=tls,
            timeout=timeout_s,
        )
        pub_status = "unknown"
        if pub.error:
            pub_status = "error"
        elif pub.timed_out and pub.rc is None:
            pub_status = "timeout_not_denial"
        elif pub.rc not in (None, 0):
            pub_status = "connect_denied"
        elif pub.connected:
            pub_status = "publish_attempted"
            if "#" in topic or "+" in topic:
                pub_status = "publish_skipped_wildcard"

        mapping.append(
            {
                "topic": topic,
                "subscribe": sub_status,
                "publish": pub_status,
                "suback_codes": sub.suback_codes,
                "connect_rc_sub": sub.rc,
                "connect_rc_pub": pub.rc,
            }
        )

    result = {
        "label": target.label,
        "target": target.key,
        "username": username,
        "mapping": mapping,
        "note": "Timeouts are classified separately from denials. QoS0 publish success is attempted, not broker-confirmed.",
    }
    session.set_module("acl", result)
    session.add_finding(
        {
            "module": "acl",
            "severity": "info",
            "title": "ACL boundary map produced",
            "target": target.key,
            "username": username,
            "topics": len(mapping),
        }
    )
    session.log_action("acl", "done", target=target.key, detail={"topics": len(mapping)})
    return result
