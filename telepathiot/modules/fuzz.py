from __future__ import annotations

import socket
from typing import Any

from telepathiot.constants import MQTT311_PROTOCOL_LEVEL
from telepathiot.mqtt.codec import encode_connect, encode_remaining_length
from telepathiot.mqtt.transport import probe_port, random_client_id
from telepathiot.rate_limit import RateLimiter
from telepathiot.scope import AuthorizedTarget
from telepathiot.session import Session


def _send(host: str, port: int, payload: bytes, timeout: float = 3.0) -> dict[str, Any]:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        try:
            sock.settimeout(timeout)
            sock.sendall(payload)
            try:
                buf = sock.recv(1024)
            except TimeoutError:
                buf = b""
            return {"sent": True, "recv_len": len(buf), "recv_hex": buf.hex()[:200]}
        finally:
            sock.close()
    except OSError as exc:
        return {"sent": False, "error": str(exc)}


def _default_corpus() -> list[tuple[str, bytes]]:
    """Conservative malformed / truncated frames. Not a crash exploit pack."""
    cid = random_client_id()
    good = encode_connect(protocol_level=MQTT311_PROTOCOL_LEVEL, client_id=cid)
    return [
        ("truncated_connect_header", b"\x10"),
        ("truncated_connect_body", good[:8]),
        ("invalid_protocol_name", b"\x10\x0c\x00\x06MQIsdp\x04\x02\x00\x1e"),
        ("reserved_packet_type_0", b"\x00\x02\x00\x00"),
        ("oversized_remaining_length_prefix", b"\x10" + encode_remaining_length(64) + b"\x00\x04MQTT"),
    ]


def _qos2_partial(client_id: str) -> bytes:
    """Opt-in: CONNECT then a PUBREC with no follow-up PUBREL/PUBCOMP."""
    return encode_connect(protocol_level=MQTT311_PROTOCOL_LEVEL, client_id=client_id)


def run_fuzz(
    target: AuthorizedTarget,
    session: Session,
    *,
    rate_limit_ms: int,
    qos2_exhaustion: bool = False,
    use_tls: bool = False,
) -> dict[str, Any]:
    if use_tls:
        raise ValueError("fuzz module speaks raw TCP only; point it at a disposable plaintext broker.")
    session.log_action(
        "fuzz",
        "start",
        target=target.key,
        detail={"rate_limit_ms": rate_limit_ms, "qos2_exhaustion": qos2_exhaustion},
    )
    baseline = probe_port(target.host, target.port)
    if not baseline.reachable:
        result = {"error": "broker_not_reachable_before_fuzz", "target": target.key}
        session.set_module("fuzz", result)
        return result

    limiter = RateLimiter(rate_limit_ms)
    cases = []
    instability = False

    for name, blob in _default_corpus():
        limiter.wait()
        session.note_connection()
        session.log_action(
            "fuzz",
            "send",
            target=target.key,
            detail={"case": name, "bytes": len(blob)},
        )
        outcome = _send(target.host, target.port, blob)
        after = probe_port(target.host, target.port)
        crashed = baseline.reachable and not after.reachable
        if crashed:
            instability = True
            session.add_finding(
                {
                    "module": "fuzz",
                    "severity": "high",
                    "title": "Broker instability after malformed packet",
                    "target": target.key,
                    "case": name,
                }
            )
            session.log_action("fuzz", "broker_instability", target=target.key, detail={"case": name}, ok=False)
        cases.append({"case": name, "outcome": outcome, "broker_up_after": after.reachable, "instability": crashed})
        if crashed:
            break

    qos2_note = None
    if qos2_exhaustion and not instability:
        limiter.wait()
        session.note_connection()
        cid = random_client_id()
        connect = _qos2_partial(cid)
        pubrec = b"\x50\x02\x00\x01"
        session.log_action("fuzz", "qos2_partial_handshake", target=target.key, detail={"opt_in": True})
        _send(target.host, target.port, connect + pubrec)
        after = probe_port(target.host, target.port)
        qos2_note = {"broker_up_after": after.reachable}
        if not after.reachable:
            instability = True
            session.add_finding(
                {
                    "module": "fuzz",
                    "severity": "high",
                    "title": "Broker instability after opt-in QoS2 partial handshake",
                    "target": target.key,
                }
            )

    result = {
        "label": target.label,
        "target": target.key,
        "baseline_open": baseline.reachable,
        "cases": cases,
        "broker_instability": instability,
        "qos2_exhaustion": qos2_exhaustion,
        "qos2_note": qos2_note,
    }
    session.set_module("fuzz", result)
    session.log_action("fuzz", "done", target=target.key, detail={"instability": instability, "cases": len(cases)})
    return result
