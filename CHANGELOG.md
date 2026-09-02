# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.0.1] — 2026-10-10

### Added

- `recon` module — anonymous-auth check, `$SYS` leak detection, MQTT 3.1.1 / 5.0 CONNACK parsing, broker fingerprint
- `topics` module — wildcard discovery, retained-message harvesting, sensitive-topic flagging
- `bruteforce` module — rate-limited CONNECT credential attack (intrusive, human-gate required)
- `acl` module — pub/sub boundary mapping per authenticated user (intrusive, human-gate required)
- `tls` module — cert validation, cipher enumeration, plaintext-beside-TLS misconfig detection
- `fuzz` module — conservative malformed-packet fuzzer on disposable broker (intrusive, human-gate required); opt-in QoS 2 partial-handshake exhaustion
- `report` subcommand — HTML session report
- `verify-env` subcommand — Docker network isolation check
- `snapshot` / `restore` subcommands — broker data-dir snapshots for safe rule-4 restore
- `agent_tools.py` — typed, scope-gated wrappers for operator / LLM agent use
- `scope.json` allowlist enforcement — every network call checks host:port against the allowlist
- `FindingsStore` — secrets written to `.findings.json` (gitignored), never printed in full
- Session action log with kill-switch flush on Ctrl+C
- Docker Compose lab stack: `broker-open`, `broker-auth`, `broker-acl`, `broker-tls`, `sim-devices`
- 14 unit tests covering codec, scope, session, and agent gate logic
