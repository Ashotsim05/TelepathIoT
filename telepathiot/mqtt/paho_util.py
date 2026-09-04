from __future__ import annotations

import ssl
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

import paho.mqtt.client as mqtt

from telepathiot.constants import CLIENT_ID_PREFIX, DEFAULT_CONNECT_TIMEOUT, DEFAULT_KEEPALIVE
from telepathiot.session import Session

_CB = getattr(mqtt, "CallbackAPIVersion", None)


def _new_client(client_id: str) -> mqtt.Client:
    if _CB is not None:
        return mqtt.Client(
            callback_api_version=_CB.VERSION2,
            client_id=client_id,
            protocol=mqtt.MQTTv311,
        )
    return mqtt.Client(client_id=client_id, protocol=mqtt.MQTTv311)


@dataclass
class Message:
    topic: str
    payload: str
    qos: int
    retain: bool


@dataclass
class PahoResult:
    connected: bool
    rc: int | None = None
    error: str | None = None
    messages: list[Message] = field(default_factory=list)
    suback_codes: list[int] = field(default_factory=list)
    puback_mid: int | None = None
    timed_out: bool = False


def subscribe_collect(
    host: str,
    port: int,
    topics: list[str],
    session: Session,
    *,
    username: str | None = None,
    password: str | None = None,
    listen_s: float = 3.0,
    use_tls: bool = False,
    tls_insecure: bool = True,
    timeout: float = DEFAULT_CONNECT_TIMEOUT,
    on_message: Callable[[Message], None] | None = None,
) -> PahoResult:
    cid = f"{CLIENT_ID_PREFIX}-{uuid.uuid4().hex[:12]}"
    session.note_connection()
    client = _new_client(cid)
    result = PahoResult(connected=False)
    connected = {"ok": False}

    def on_connect(c, userdata, flags, reason_code, properties=None):
        rc = int(getattr(reason_code, "value", reason_code))
        result.rc = rc
        connected["ok"] = rc == 0
        result.connected = rc == 0
        if rc == 0:
            pairs = [(t, 0) for t in topics]
            c.subscribe(pairs)

    def on_subscribe(c, userdata, mid, reason_codes, properties=None):
        codes = []
        for item in reason_codes if isinstance(reason_codes, (list, tuple)) else [reason_codes]:
            codes.append(int(getattr(item, "value", item)))
        result.suback_codes = codes

    def _on_message(c, userdata, msg):
        payload = msg.payload.decode("utf-8", errors="replace")
        m = Message(msg.topic, payload, msg.qos, bool(msg.retain))
        result.messages.append(m)
        if on_message:
            on_message(m)

    client.on_connect = on_connect
    client.on_subscribe = on_subscribe
    client.on_message = _on_message
    if username is not None:
        client.username_pw_set(username, password)
    if use_tls:
        client.tls_set(cert_reqs=ssl.CERT_NONE if tls_insecure else ssl.CERT_REQUIRED)
        if tls_insecure:
            client.tls_insecure_set(True)

    session.log_action(
        "mqtt",
        "SUBSCRIBE",
        target=f"{host}:{port}",
        detail={"client_id": cid, "topics": topics, "username": username, "tls": use_tls},
    )
    try:
        client.connect(host, port, keepalive=DEFAULT_KEEPALIVE)
        client.loop_start()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and result.rc is None:
            time.sleep(0.05)
        if result.connected:
            time.sleep(max(0.0, listen_s))
        else:
            result.timed_out = result.rc is None
    except Exception as exc:
        result.error = str(exc)
        session.log_action(
            "mqtt",
            "SUBSCRIBE",
            target=f"{host}:{port}",
            detail={"error": str(exc)},
            ok=False,
        )
    finally:
        try:
            client.loop_stop()
            client.disconnect()
        except Exception:
            pass
    return result


def publish_once(
    host: str,
    port: int,
    topic: str,
    payload: bytes | str,
    session: Session,
    *,
    username: str | None = None,
    password: str | None = None,
    qos: int = 0,
    retain: bool = False,
    use_tls: bool = False,
    tls_insecure: bool = True,
    timeout: float = DEFAULT_CONNECT_TIMEOUT,
) -> PahoResult:
    """Publish with retain=False by default (hard rule)."""
    cid = f"{CLIENT_ID_PREFIX}-{uuid.uuid4().hex[:12]}"
    session.note_connection()
    client = _new_client(cid)
    result = PahoResult(connected=False)
    if username is not None:
        client.username_pw_set(username, password)
    if use_tls:
        client.tls_set(cert_reqs=ssl.CERT_NONE if tls_insecure else ssl.CERT_REQUIRED)
        if tls_insecure:
            client.tls_insecure_set(True)

    def on_connect(c, userdata, flags, reason_code, properties=None):
        rc = int(getattr(reason_code, "value", reason_code))
        result.rc = rc
        result.connected = rc == 0
        if rc == 0:
            info = c.publish(topic, payload, qos=qos, retain=retain)
            result.puback_mid = info.mid

    client.on_connect = on_connect
    session.log_action(
        "mqtt",
        "PUBLISH",
        target=f"{host}:{port}",
        detail={
            "client_id": cid,
            "topic": topic,
            "qos": qos,
            "retain": retain,
            "payload_len": len(payload) if isinstance(payload, (bytes, str)) else 0,
            "username": username,
        },
    )
    try:
        client.connect(host, port, keepalive=DEFAULT_KEEPALIVE)
        client.loop_start()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and result.rc is None:
            time.sleep(0.05)
        if result.connected:
            time.sleep(0.2)
    except Exception as exc:
        result.error = str(exc)
        session.log_action(
            "mqtt",
            "PUBLISH",
            target=f"{host}:{port}",
            detail={"error": str(exc), "topic": topic},
            ok=False,
        )
    finally:
        try:
            client.loop_stop()
            client.disconnect()
        except Exception:
            pass
    return result
