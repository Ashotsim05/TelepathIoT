from __future__ import annotations

import socket
import ssl
import time
import uuid
from dataclasses import dataclass
from typing import Any

from telepathiot.constants import (
    CLIENT_ID_PREFIX,
    DEFAULT_CONNECT_TIMEOUT,
    MQTT311_PROTOCOL_LEVEL,
    MQTT50_PROTOCOL_LEVEL,
)
from telepathiot.mqtt.codec import ConnackResult, encode_connect, parse_incoming
from telepathiot.session import Session


def random_client_id() -> str:
    return f"{CLIENT_ID_PREFIX}-{uuid.uuid4().hex[:12]}"


@dataclass
class TcpProbe:
    reachable: bool
    elapsed_ms: float
    error: str | None = None


def probe_port(host: str, port: int, timeout: float = DEFAULT_CONNECT_TIMEOUT) -> TcpProbe:
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return TcpProbe(True, (time.monotonic() - start) * 1000)
    except OSError as exc:
        return TcpProbe(False, (time.monotonic() - start) * 1000, str(exc))


def raw_connect(
    host: str,
    port: int,
    *,
    protocol_level: int,
    session: Session,
    username: str | None = None,
    password: str | None = None,
    timeout: float = DEFAULT_CONNECT_TIMEOUT,
    use_tls: bool = False,
    tls_insecure: bool = True,
    client_id: str | None = None,
) -> ConnackResult:
    session.note_connection()
    cid = client_id or random_client_id()
    pkt = encode_connect(
        protocol_level=protocol_level,
        client_id=cid,
        username=username,
        password=password,
    )
    proto = "mqtt5" if protocol_level == MQTT50_PROTOCOL_LEVEL else "mqtt311"
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            if tls_insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        sock.sendall(pkt)
        buf = sock.recv(4096)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    result = parse_incoming(buf, protocol_level)
    session.log_action(
        "mqtt",
        "CONNECT",
        target=f"{host}:{port}",
        detail={
            "protocol": proto,
            "client_id": cid,
            "username": username,
            "has_password": bool(password),
            "tls": use_tls,
            "packet_type": result.packet_type,
            "reason_name": result.reason_name,
            "accepted": result.accepted,
            "enhanced_auth": result.enhanced_auth,
        },
        ok=True,
    )
    return result


def connect_both_versions(
    host: str,
    port: int,
    session: Session,
    **kwargs: Any,
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, level in (("mqtt311", MQTT311_PROTOCOL_LEVEL), ("mqtt5", MQTT50_PROTOCOL_LEVEL)):
        try:
            out[name] = raw_connect(host, port, protocol_level=level, session=session, **kwargs).to_dict()
        except OSError as exc:
            out[name] = {"error": str(exc), "accepted": False}
            session.log_action(
                "mqtt",
                "CONNECT",
                target=f"{host}:{port}",
                detail={"protocol": name, "error": str(exc)},
                ok=False,
            )
        except Exception as exc:
            out[name] = {"error": str(exc), "accepted": False}
            session.log_action(
                "mqtt",
                "CONNECT_PARSE",
                target=f"{host}:{port}",
                detail={"protocol": name, "error": str(exc)},
                ok=False,
            )
    return out
