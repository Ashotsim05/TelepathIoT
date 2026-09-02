"""Unit tests — no live broker required."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from telepathiot.constants import MQTT311_PROTOCOL_LEVEL, MQTT50_PROTOCOL_LEVEL
from telepathiot.mqtt.codec import (
    encode_connect,
    encode_remaining_length,
    parse_incoming,
)
from telepathiot.scope import ScopeError, canonicalize_host, load_scope
from telepathiot.secrets import redact_value


def test_remaining_length_roundtrip() -> None:
    for n in (0, 127, 128, 16383, 2097151):
        enc = encode_remaining_length(n)
        # decode expects a dummy fixed header byte
        from telepathiot.mqtt.codec import decode_remaining_length

        val, _ = decode_remaining_length(b"\x10" + enc, 1)
        assert val == n


def test_connack_mqtt311_accepted() -> None:
    # CONNACK, remaining 2, session 0, rc 0
    pkt = bytes([0x20, 0x02, 0x00, 0x00])
    r = parse_incoming(pkt, MQTT311_PROTOCOL_LEVEL)
    assert r.accepted
    assert r.return_code == 0
    assert r.reason_name == "accepted"
    assert not r.enhanced_auth


def test_connack_mqtt311_not_authorized() -> None:
    pkt = bytes([0x20, 0x02, 0x00, 0x05])
    r = parse_incoming(pkt, MQTT311_PROTOCOL_LEVEL)
    assert not r.accepted
    assert r.return_code == 5
    assert r.reason_name == "not_authorized"


def test_connack_mqtt5_reason_string() -> None:
    # CONNACK remaining length computed: flags+reason+props
    # properties: reason string identifier 0x1F, utf8 "nope"
    reason = b"nope"
    props = bytes([0x1F, 0x00, len(reason)]) + reason
    prop_len = bytes([len(props)])
    variable = bytes([0x00, 0x87]) + prop_len + props
    pkt = bytes([0x20, len(variable)]) + variable
    r = parse_incoming(pkt, MQTT50_PROTOCOL_LEVEL)
    assert r.protocol == "mqtt5"
    assert r.reason_code == 0x87
    assert r.reason_name == "not_authorized"
    assert r.reason_string == "nope"
    assert not r.accepted


def test_auth_packet_flags_enhanced_auth() -> None:
    # AUTH, remaining 2, continue (0x18), empty props 0
    pkt = bytes([0xF0, 0x02, 0x18, 0x00])
    r = parse_incoming(pkt, MQTT50_PROTOCOL_LEVEL)
    assert r.packet_type == "AUTH"
    assert r.enhanced_auth
    assert not r.accepted


def test_connect_encodes_client_id() -> None:
    pkt = encode_connect(protocol_level=MQTT311_PROTOCOL_LEVEL, client_id="tpiot-abc")
    assert pkt[0] == 0x10
    assert b"tpiot-abc" in pkt
    assert b"MQTT" in pkt


def test_scope_allowlist(tmp_path: Path) -> None:
    p = tmp_path / "scope.json"
    p.write_text(
        json.dumps(
            {
                "authorized_targets": [
                    {"label": "lab", "host": "127.0.0.1", "port": 1883}
                ]
            }
        ),
        encoding="utf-8",
    )
    scope = load_scope(p)
    assert scope.require("localhost", 1883).label == "lab"
    with pytest.raises(ScopeError):
        scope.require("8.8.8.8", 1883)


def test_canonicalize_localhost() -> None:
    assert canonicalize_host("localhost") == "127.0.0.1"


def test_redact_stable() -> None:
    a = redact_value("labpass")
    b = redact_value("labpass")
    assert a == b
    assert "labpass" not in a
    assert a.startswith("[REDACTED:")
