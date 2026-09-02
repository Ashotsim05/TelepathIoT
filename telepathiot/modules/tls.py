from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from telepathiot.mqtt.transport import probe_port
from telepathiot.scope import AuthorizedTarget, Scope
from telepathiot.session import Session

# Representative TLS 1.2/1.3 suites to probe; not an exhaustive attack list.
PROBE_CIPHERS = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "AES256-GCM-SHA384",
    "AES128-SHA",
    "RC4-SHA",
    "DES-CBC3-SHA",
]


def _try_handshake(
    host: str,
    port: int,
    *,
    verify: bool,
    cipher: str | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    if cipher:
        try:
            ctx.set_ciphers(cipher)
        except ssl.SSLError as exc:
            return {"ok": False, "error": f"cipher_not_supported_locally:{exc}"}
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        try:
            sock = ctx.wrap_socket(raw, server_hostname=host)
            cert = sock.getpeercert()
            cipher_info = sock.cipher()
            version = sock.version()
            sock.close()
        finally:
            try:
                raw.close()
            except OSError:
                pass
        return {
            "ok": True,
            "verify": verify,
            "tls_version": version,
            "cipher": cipher_info,
            "cert": cert,
        }
    except ssl.SSLCertVerificationError as exc:
        return {"ok": False, "verify": verify, "error": "cert_validation_failed", "detail": str(exc)}
    except OSError as exc:
        return {"ok": False, "verify": verify, "error": str(exc), "cipher": cipher}


def run_tls(
    target: AuthorizedTarget,
    session: Session,
    scope: Scope,
    *,
    plaintext_port: int | None = None,
) -> dict[str, Any]:
    session.log_action("tls", "start", target=target.key, detail={"label": target.label})
    host, port = target.host, target.port

    insecure = _try_handshake(host, port, verify=False)
    session.log_action("tls", "handshake_insecure", target=target.key, detail={"ok": insecure.get("ok")})
    verifying = _try_handshake(host, port, verify=True)
    session.log_action(
        "tls",
        "handshake_verifying",
        target=target.key,
        detail={"ok": verifying.get("ok"), "error": verifying.get("error")},
        ok=verifying.get("ok", False),
    )

    ciphers: list[dict[str, Any]] = []
    for name in PROBE_CIPHERS:
        hit = _try_handshake(host, port, verify=False, cipher=name)
        ciphers.append({"cipher": name, "accepted": bool(hit.get("ok")), "error": hit.get("error")})
        session.log_action(
            "tls",
            "cipher_probe",
            target=target.key,
            detail={"cipher": name, "accepted": bool(hit.get("ok"))},
        )

    check_port = plaintext_port
    if check_port is None:
        # Common misconfig: plaintext still bound. Prefer a scoped sibling, else 1883.
        sibling = scope.find(host, 1886) or scope.find(host, 1883)
        check_port = sibling.port if sibling else 1883

    plaintext_ok = False
    plaintext_in_scope = False
    try:
        scope.require(host, check_port)
        plaintext_in_scope = True
        probe = probe_port(host, check_port)
        plaintext_ok = probe.reachable
        session.log_action(
            "tls",
            "plaintext_port_check",
            target=f"{host}:{check_port}",
            detail={"open": plaintext_ok},
        )
    except Exception as exc:
        session.log_action(
            "tls",
            "plaintext_port_skipped",
            target=f"{host}:{check_port}",
            detail={"reason": str(exc)},
            ok=False,
        )

    cert = insecure.get("cert") or {}
    not_after = None
    if isinstance(cert, dict):
        not_after = cert.get("notAfter")

    result = {
        "label": target.label,
        "target": target.key,
        "handshake_without_verify": bool(insecure.get("ok")),
        "handshake_with_verify": bool(verifying.get("ok")),
        "verify_error": verifying.get("error") or verifying.get("detail"),
        "peer_cert_summary": {
            "subject": cert.get("subject") if isinstance(cert, dict) else None,
            "issuer": cert.get("issuer") if isinstance(cert, dict) else None,
            "notAfter": not_after,
        },
        "ciphers": ciphers,
        "plaintext_port": check_port,
        "plaintext_port_in_scope": plaintext_in_scope,
        "plaintext_still_open": plaintext_ok,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    if not verifying.get("ok"):
        session.add_finding(
            {
                "module": "tls",
                "severity": "medium",
                "title": "TLS certificate does not validate against system CAs",
                "target": target.key,
                "detail": verifying.get("detail") or verifying.get("error"),
            }
        )
    if plaintext_ok:
        session.add_finding(
            {
                "module": "tls",
                "severity": "high",
                "title": "Plaintext MQTT still reachable beside TLS",
                "target": f"{host}:{check_port}",
                "tls_port": port,
            }
        )
    weak = [c["cipher"] for c in ciphers if c["accepted"] and c["cipher"] in {"RC4-SHA", "DES-CBC3-SHA", "AES128-SHA"}]
    if weak:
        session.add_finding(
            {
                "module": "tls",
                "severity": "medium",
                "title": "Legacy/weak ciphers accepted",
                "target": target.key,
                "ciphers": weak,
            }
        )

    session.set_module("tls", result)
    session.log_action("tls", "done", target=target.key)
    return result
