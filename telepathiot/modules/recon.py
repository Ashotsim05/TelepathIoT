from __future__ import annotations

from typing import Any

from telepathiot.mqtt.codec import fingerprint
from telepathiot.mqtt.paho_util import subscribe_collect
from telepathiot.mqtt.transport import connect_both_versions, probe_port
from telepathiot.scope import AuthorizedTarget
from telepathiot.secrets import looks_secret, redact_value
from telepathiot.session import Session

SYS_PROBE_TOPICS = [
    "$SYS/#",
    "$SYS/broker/version",
    "$SYS/broker/uptime",
    "$SYS/broker/clients/connected",
]


def run_recon(
    target: AuthorizedTarget,
    session: Session,
    *,
    listen_s: float = 2.0,
    use_tls: bool | None = None,
) -> dict[str, Any]:
    tls = use_tls if use_tls is not None else target.protocol == "mqtts"
    host, port = target.host, target.port
    session.log_action("recon", "start", target=target.key, detail={"label": target.label, "tls": tls})

    port_state = probe_port(host, port)
    session.log_action(
        "recon",
        "tcp_probe",
        target=target.key,
        detail={"reachable": port_state.reachable, "elapsed_ms": round(port_state.elapsed_ms, 2)},
        ok=port_state.reachable,
    )

    result: dict[str, Any] = {
        "label": target.label,
        "target": target.key,
        "port_open": port_state.reachable,
        "tcp_error": port_state.error,
        "anonymous": None,
        "protocols": {},
        "enhanced_auth": False,
        "enhanced_auth_note": None,
        "sys_leak": {"disclosed": False, "topics": []},
        "fingerprint": [],
        "bruteforce_in_scope": True,
    }

    if not port_state.reachable:
        session.set_module("recon", result)
        session.add_finding(
            {
                "module": "recon",
                "severity": "info",
                "title": "Port closed or unreachable",
                "target": target.key,
            }
        )
        return result

    protocols = connect_both_versions(host, port, session, use_tls=tls)
    result["protocols"] = protocols
    anon_ok = bool(
        (protocols.get("mqtt311") or {}).get("accepted")
        or (protocols.get("mqtt5") or {}).get("accepted")
    )
    result["anonymous"] = anon_ok

    for proto, body in protocols.items():
        if isinstance(body, dict) and body.get("enhanced_auth"):
            result["enhanced_auth"] = True
            result["bruteforce_in_scope"] = False
            result["enhanced_auth_note"] = (
                "Broker issued AUTH / enhanced-auth CONNACK. Username/password "
                "bruteforce is out of scope for this target (would be a false negative)."
            )
        if isinstance(body, dict) and body.get("packet_type") == "AUTH":
            result["enhanced_auth"] = True
            result["bruteforce_in_scope"] = False

    if anon_ok:
        session.add_finding(
            {
                "module": "recon",
                "severity": "high",
                "title": "Anonymous MQTT connect accepted",
                "target": target.key,
                "known_answer": target.label == "broker-open",
            }
        )
    else:
        session.add_finding(
            {
                "module": "recon",
                "severity": "info",
                "title": "Anonymous MQTT connect rejected",
                "target": target.key,
                "known_answer": target.label in {"broker-auth", "broker-acl"},
            }
        )

    if result["enhanced_auth"]:
        session.add_finding(
            {
                "module": "recon",
                "severity": "medium",
                "title": "MQTT 5 enhanced authentication detected",
                "target": target.key,
                "detail": result["enhanced_auth_note"],
            }
        )

    sys_payloads: dict[str, str] = {}
    sys_topics: list[str] = []
    if anon_ok:
        collected = subscribe_collect(
            host,
            port,
            SYS_PROBE_TOPICS,
            session,
            listen_s=listen_s,
            use_tls=tls,
        )
        for msg in collected.messages:
            if msg.topic.startswith("$SYS"):
                sys_topics.append(msg.topic)
                payload = msg.payload
                if looks_secret(msg.topic, payload):
                    payload = redact_value(payload)
                sys_payloads[msg.topic] = payload[:200]
        result["sys_leak"] = {
            "disclosed": bool(sys_topics),
            "topic_count": len(sys_topics),
            "topics": sorted(set(sys_topics))[:50],
            "samples": {k: sys_payloads[k] for k in list(sys_payloads)[:20]},
            "subscribe_denied": bool(collected.suback_codes) and all(c >= 128 for c in collected.suback_codes),
            "connected": collected.connected,
        }
        if sys_topics:
            session.add_finding(
                {
                    "module": "recon",
                    "severity": "medium",
                    "title": "$SYS topic tree discloses broker metadata",
                    "target": target.key,
                    "topic_count": len(set(sys_topics)),
                    "samples": result["sys_leak"]["samples"],
                }
            )

    reason_string = None
    for body in protocols.values():
        if isinstance(body, dict) and body.get("reason_string"):
            reason_string = body["reason_string"]
    result["fingerprint"] = fingerprint(
        sys_topics=list(sys_payloads.keys()),
        sys_payloads=sys_payloads,
        connack_reason_string=reason_string,
    )

    session.set_module("recon", result)
    session.log_action("recon", "done", target=target.key, detail={"anonymous": anon_ok})
    return result
