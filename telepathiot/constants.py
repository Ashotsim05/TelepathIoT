DEFAULT_RATE_LIMIT_MS = 200
DEFAULT_KEEPALIVE = 30
DEFAULT_CONNECT_TIMEOUT = 5.0
CLIENT_ID_PREFIX = "tpiot"
FINDINGS_FILENAME = ".findings.json"
SESSION_DIR = "sessions"
ACTION_LOG_NAME = "actions.log"

PKT_CONNECT = 1
PKT_CONNACK = 2
PKT_PUBLISH = 3
PKT_PUBACK = 4
PKT_PUBREC = 5
PKT_PUBREL = 6
PKT_PUBCOMP = 7
PKT_SUBSCRIBE = 8
PKT_SUBACK = 9
PKT_UNSUBSCRIBE = 10
PKT_UNSUBACK = 11
PKT_PINGREQ = 12
PKT_PINGRESP = 13
PKT_DISCONNECT = 14
PKT_AUTH = 15

MQTT311_PROTOCOL_LEVEL = 4
MQTT50_PROTOCOL_LEVEL = 5

MQTT311_CONNACK = {
    0: "accepted",
    1: "unacceptable_protocol_version",
    2: "identifier_rejected",
    3: "server_unavailable",
    4: "bad_username_or_password",
    5: "not_authorized",
}

MQTT5_CONNACK_REASON = {
    0x00: "success",
    0x80: "unspecified_error",
    0x81: "malformed_packet",
    0x82: "protocol_error",
    0x83: "implementation_specific_error",
    0x84: "unsupported_protocol_version",
    0x85: "client_identifier_not_valid",
    0x86: "bad_username_or_password",
    0x87: "not_authorized",
    0x88: "server_unavailable",
    0x89: "server_busy",
    0x8A: "banned",
    0x8C: "bad_authentication_method",
    0x90: "topic_name_invalid",
    0x95: "packet_too_large",
    0x97: "quota_exceeded",
    0x99: "payload_format_invalid",
    0x9A: "retain_not_supported",
    0x9B: "qos_not_supported",
    0x9C: "use_another_server",
    0x9D: "server_moved",
    0x9F: "connection_rate_exceeded",
}

INTRUSIVE_MODULES = frozenset({"bruteforce", "acl", "fuzz"})
PASSIVE_MODULES = frozenset({"recon", "topics", "tls", "report"})
