from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

from telepathiot.constants import (
    MQTT311_CONNACK,
    MQTT311_PROTOCOL_LEVEL,
    MQTT50_PROTOCOL_LEVEL,
    MQTT5_CONNACK_REASON,
    PKT_AUTH,
    PKT_CONNACK,
    PKT_CONNECT,
)


class PacketError(Exception):
    pass


def encode_remaining_length(length: int) -> bytes:
    if length < 0 or length > 268_435_455:
        raise PacketError("remaining length out of range")
    out = bytearray()
    while True:
        encoded = length % 128
        length //= 128
        if length > 0:
            encoded |= 0x80
        out.append(encoded)
        if length == 0:
            break
    return bytes(out)


def decode_remaining_length(buf: bytes, offset: int = 1) -> tuple[int, int]:
    multiplier = 1
    value = 0
    pos = offset
    for _ in range(4):
        if pos >= len(buf):
            raise PacketError("truncated remaining length")
        byte = buf[pos]
        pos += 1
        value += (byte & 127) * multiplier
        if byte & 128 == 0:
            return value, pos
        multiplier *= 128
    raise PacketError("malformed remaining length")


def encode_utf8(s: str) -> bytes:
    raw = s.encode("utf-8")
    if len(raw) > 65535:
        raise PacketError("utf8 string too long")
    return struct.pack("!H", len(raw)) + raw


def read_utf8(buf: bytes, pos: int) -> tuple[str, int]:
    if pos + 2 > len(buf):
        raise PacketError("truncated utf8 length")
    (n,) = struct.unpack_from("!H", buf, pos)
    pos += 2
    if pos + n > len(buf):
        raise PacketError("truncated utf8 body")
    return buf[pos : pos + n].decode("utf-8", errors="replace"), pos + n


def encode_connect(
    *,
    protocol_level: int,
    client_id: str,
    username: str | None = None,
    password: str | None = None,
    keep_alive: int = 30,
    clean_start: bool = True,
    authentication_method: str | None = None,
) -> bytes:
    """Build a CONNECT packet. retain is N/A here; password is binary-safe."""
    proto_name = encode_utf8("MQTT")
    flags = 0
    if clean_start:
        flags |= 0x02
    payload = encode_utf8(client_id)
    properties = b""
    if protocol_level == MQTT50_PROTOCOL_LEVEL:
        props = bytearray()
        if authentication_method:
            props.append(0x15)
            props.extend(encode_utf8(authentication_method))
        properties = encode_remaining_length(len(props)) + bytes(props)
    if username is not None:
        flags |= 0x80
        payload += encode_utf8(username)
    if password is not None:
        flags |= 0x40
        pw = password.encode("utf-8")
        payload += struct.pack("!H", len(pw)) + pw
    variable = proto_name + bytes([protocol_level, flags]) + struct.pack("!H", keep_alive)
    if protocol_level == MQTT50_PROTOCOL_LEVEL:
        variable += properties
    variable += payload
    header = bytes([PKT_CONNECT << 4]) + encode_remaining_length(len(variable))
    return header + variable


@dataclass
class ConnackResult:
    protocol: str
    packet_type: str
    session_present: bool
    return_code: int | None
    reason_code: int | None
    reason_name: str
    reason_string: str | None
    properties: dict[str, Any]
    enhanced_auth: bool
    raw_hex: str
    accepted: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "packet_type": self.packet_type,
            "session_present": self.session_present,
            "return_code": self.return_code,
            "reason_code": self.reason_code,
            "reason_name": self.reason_name,
            "reason_string": self.reason_string,
            "properties": self.properties,
            "enhanced_auth": self.enhanced_auth,
            "accepted": self.accepted,
            "raw_hex": self.raw_hex,
        }


def parse_incoming(buf: bytes, protocol_level: int) -> ConnackResult:
    if not buf:
        raise PacketError("empty response")
    ptype = buf[0] >> 4
    raw_hex = buf.hex()
    if ptype == PKT_AUTH:
        return _parse_auth(buf, protocol_level, raw_hex)
    if ptype != PKT_CONNACK:
        return ConnackResult(
            protocol="mqtt5" if protocol_level == MQTT50_PROTOCOL_LEVEL else "mqtt311",
            packet_type=f"other_{ptype}",
            session_present=False,
            return_code=None,
            reason_code=None,
            reason_name=f"unexpected_packet_type_{ptype}",
            reason_string=None,
            properties={},
            enhanced_auth=False,
            raw_hex=raw_hex,
            accepted=False,
        )
    if protocol_level == MQTT50_PROTOCOL_LEVEL:
        return _parse_connack_v5(buf, raw_hex)
    return _parse_connack_v311(buf, raw_hex)


def _parse_connack_v311(buf: bytes, raw_hex: str) -> ConnackResult:
    _len, pos = decode_remaining_length(buf, 1)
    if pos + 2 > len(buf):
        raise PacketError("truncated MQTT 3.1.1 CONNACK")
    ack_flags = buf[pos]
    rc = buf[pos + 1]
    name = MQTT311_CONNACK.get(rc, f"unknown_{rc}")
    return ConnackResult(
        protocol="mqtt311",
        packet_type="CONNACK",
        session_present=bool(ack_flags & 0x01),
        return_code=rc,
        reason_code=None,
        reason_name=name,
        reason_string=None,
        properties={},
        enhanced_auth=False,
        raw_hex=raw_hex,
        accepted=rc == 0,
    )


def _parse_properties(buf: bytes, pos: int) -> tuple[dict[str, Any], int]:
    if pos >= len(buf):
        return {}, pos
    prop_len, pos = _read_varint_at(buf, pos)
    end = pos + prop_len
    props: dict[str, Any] = {}
    while pos < end:
        ident = buf[pos]
        pos += 1
        if ident == 0x1F:
            s, pos = read_utf8(buf, pos)
            props["reason_string"] = s
        elif ident == 0x15:
            s, pos = read_utf8(buf, pos)
            props["authentication_method"] = s
        elif ident == 0x16:
            if pos + 2 > len(buf):
                break
            (n,) = struct.unpack_from("!H", buf, pos)
            pos += 2 + n
            props["authentication_data_len"] = n
        elif ident == 0x26:
            k, pos = read_utf8(buf, pos)
            v, pos = read_utf8(buf, pos)
            props.setdefault("user_properties", []).append({"key": k, "value": v})
        else:
            break
    return props, pos


def _read_varint_at(buf: bytes, pos: int) -> tuple[int, int]:
    multiplier = 1
    value = 0
    for _ in range(4):
        if pos >= len(buf):
            raise PacketError("truncated property length")
        byte = buf[pos]
        pos += 1
        value += (byte & 127) * multiplier
        if byte & 128 == 0:
            return value, pos
        multiplier *= 128
    raise PacketError("malformed property length")


def _parse_connack_v5(buf: bytes, raw_hex: str) -> ConnackResult:
    _len, pos = decode_remaining_length(buf, 1)
    if pos + 2 > len(buf):
        raise PacketError("truncated MQTT 5.0 CONNACK")
    ack_flags = buf[pos]
    reason = buf[pos + 1]
    pos += 2
    props, _ = _parse_properties(buf, pos) if pos < len(buf) else ({}, pos)
    name = MQTT5_CONNACK_REASON.get(reason, f"unknown_{reason:#x}")
    return ConnackResult(
        protocol="mqtt5",
        packet_type="CONNACK",
        session_present=bool(ack_flags & 0x01),
        return_code=None,
        reason_code=reason,
        reason_name=name,
        reason_string=props.get("reason_string"),
        properties=props,
        enhanced_auth=reason in {0x18, 0x19} or "authentication_method" in props,
        raw_hex=raw_hex,
        accepted=reason == 0x00,
    )


def _parse_auth(buf: bytes, protocol_level: int, raw_hex: str) -> ConnackResult:
    _len, pos = decode_remaining_length(buf, 1)
    reason = buf[pos] if pos < len(buf) else None
    pos = pos + 1 if pos < len(buf) else pos
    props, _ = _parse_properties(buf, pos) if pos < len(buf) else ({}, pos)
    return ConnackResult(
        protocol="mqtt5",
        packet_type="AUTH",
        session_present=False,
        return_code=None,
        reason_code=reason,
        reason_name="enhanced_authentication",
        reason_string=props.get("reason_string"),
        properties=props,
        enhanced_auth=True,
        raw_hex=raw_hex,
        accepted=False,
    )


@dataclass
class BrokerSignature:
    name: str
    version_topics: list[str]
    sys_prefixes: list[str]
    connack_reason_hints: list[str] = field(default_factory=list)


SIGNATURES = [
    BrokerSignature(
        name="Eclipse Mosquitto",
        version_topics=["$SYS/broker/version"],
        sys_prefixes=["$SYS/broker/"],
        connack_reason_hints=["Connection refused"],
    ),
    BrokerSignature(
        name="EMQX",
        version_topics=["$SYS/brokers/+/version"],
        sys_prefixes=["$SYS/brokers/"],
        connack_reason_hints=["Not authorized"],
    ),
    BrokerSignature(
        name="HiveMQ",
        version_topics=[],
        sys_prefixes=["$SYS/"],
        connack_reason_hints=["Client identifier not valid"],
    ),
    BrokerSignature(
        name="VerneMQ",
        version_topics=["$SYS/broker/version"],
        sys_prefixes=["$SYS/"],
        connack_reason_hints=[],
    ),
]


def fingerprint(
    *,
    sys_topics: list[str],
    sys_payloads: dict[str, str],
    connack_reason_string: str | None,
) -> list[dict[str, Any]]:
    hits = []
    for sig in SIGNATURES:
        score = 0
        reasons = []
        for topic in sys_topics:
            if any(topic.startswith(p.rstrip("#").rstrip("+").rstrip("/")) or p.rstrip("#") in topic for p in sig.sys_prefixes):
                score += 1
                reasons.append(f"sys_prefix:{sig.sys_prefixes[0]}")
                break
        for vt in sig.version_topics:
            key = vt.replace("+", "").replace("#", "")
            for t, payload in sys_payloads.items():
                if t == vt or (key and key in t):
                    score += 2
                    reasons.append(f"version_topic:{t}={payload[:80]}")
        if connack_reason_string:
            for hint in sig.connack_reason_hints:
                if hint.lower() in connack_reason_string.lower():
                    score += 1
                    reasons.append(f"connack_hint:{hint}")
        if score:
            hits.append({"broker": sig.name, "score": score, "reasons": reasons})
    hits.sort(key=lambda h: h["score"], reverse=True)
    return hits
