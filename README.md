# TelepathIoT

Isolated-lab toolkit for assessing MQTT broker configuration, authentication, ACLs, TLS, and protocol handling.

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![MQTT 3.1.1 / 5.0](https://img.shields.io/badge/MQTT-3.1.1%20%2F%205.0-orange)](https://mqtt.org/)
[![Lab only](https://img.shields.io/badge/use-authorized%20lab%20only-red)](#disclaimer)

TelepathIoT is intended for **authorized security testing against brokers you control**. Every network contact is checked against a local `scope.json` allowlist. The bundled Docker stack runs on an **internal** network with simulated devices only.

---

## Overview

MQTT brokers in IoT deployments are often left with anonymous access, weak credentials, leaky `$SYS` trees, or TLS that still exposes plaintext on 1883. TelepathIoT walks a known-answer lab matrix so you can validate the tool against expected findings before you ever point it at a less controlled target.

| Module | Role | Risk |
| --- | --- | --- |
| `recon` | Port state, protocol negotiation, anonymous connect, `$SYS` disclosure, broker fingerprint | Passive |
| `topics` | Wildcard discovery, retained messages, sensitive-topic flagging | Read-mostly |
| `tls` | Certificate validation, cipher probe, plaintext-beside-TLS | Passive |
| `bruteforce` | Rate-limited CONNECT username/password | Intrusive |
| `acl` | Publish vs subscribe boundary map | Intrusive |
| `fuzz` | Conservative malformed packets; optional QoS 2 partial handshake | Intrusive |
| `report` | HTML report from `session.json` | None |

Intrusive modules require an interactive `go` confirmation, or `--i-confirm-intrusive` for lab automation.

## Safety model

1. **Allowlist only.** Hosts and ports not listed in `scope.json` are refused (exit code 2).
2. **Isolated lab network.** Brokers sit on Docker network `telepathiot-lab` with `internal: true`. Run `telepathiot verify-env` before every session.
3. **Simulated devices.** The compose stack ships `sim-devices`. Do not attach real firmware unless you have separate, explicit authorization.
4. **Rate limits.** Default **200 ms** between intrusive attempts. Unthrottled CONNECT storms can crash small brokers and produce a DoS, not an auth finding.
5. **Snapshot / restore.** Retained-message and ACL tests mutate broker state. Snapshot data directories before those runs.
6. **Kill switch.** Ctrl+C flushes `sessions/<id>.session.json` and the action log.
7. **Secret handling.** Passwords and tokens are written to gitignored `.findings.json` and appear in reports only as redacted handles.
8. **Evidence trail.** Every send is logged (what, when, target), not only successful findings.

Protocol notes that affect results:

- MQTT **3.1.1** and **5.0** CONNACK are parsed separately (return code vs reason code / reason string).
- An **AUTH** packet (enhanced authentication) marks CONNECT bruteforce **out of scope** — not “not vulnerable”.
- Client IDs are random per connection (`tpiot-*`) to avoid kicking other sessions.
- Publish defaults to `retain=False`.
- `$SYS/#` is a dedicated recon check, not buried in general topic discovery.

## Requirements

- Python **3.11+**
- Docker Engine with Compose v2 (for the lab)
- Optional: `mosquitto_pub` / `mosquitto_sub` to establish ground truth before a tool run

## Installation

```bash
git clone https://github.com/Ashotsim05/TelepathIoT.git
cd TelepathIoT
python -m pip install -e ".[dev]"
copy scope.example.json scope.json   # Windows
# cp scope.example.json scope.json  # macOS / Linux
```

Edit `scope.json` so it lists only brokers you are authorized to test. The example file matches the local lab listeners.

## Lab environment

```bash
cd lab
docker compose up --build -d
cd ..
python -m telepathiot verify-env
```

`verify-env` inspects `telepathiot-lab` and refuses to proceed if the network is not internal.

| Service | Host bind | Known-answer behavior |
| --- | --- | --- |
| `broker-open` | `127.0.0.1:1883` | Anonymous connect allowed; `$SYS` metadata; live sim topics |
| `broker-auth` | `127.0.0.1:1884` | Anonymous rejected; planted user `labuser` / `labpass` |
| `broker-acl` | `127.0.0.1:1885` | User `sensor` cannot subscribe to `#` or `admin/#` |
| `broker-tls` | `127.0.0.1:8883` | TLS listener (lab CA) |
| `broker-tls-plaintext` | `127.0.0.1:1886` | Deliberate misconfig: plaintext still open beside TLS |
| `sim-devices` | internal only | Temperature, GPS, retained honeypot `admin/token` |

Confirm each listener with Mosquitto clients before trusting TelepathIoT output.

Broker data directories are bind-mounted under `lab/brokers/*/data` so you can snapshot and restore:

```bash
python -m telepathiot snapshot --name pre --lab-dir lab
python -m telepathiot restore --name pre --lab-dir lab
```

## Usage

Recon and topic discovery (passive / read-mostly):

```bash
python -m telepathiot recon --target broker-open
python -m telepathiot recon --target broker-auth
python -m telepathiot topics --target broker-open
python -m telepathiot tls --target broker-tls
```

Intrusive modules (human gate required):

```bash
python -m telepathiot snapshot --name pre-brute --lab-dir lab
python -m telepathiot bruteforce --target broker-auth \
  --users lab/wordlists/users.txt \
  --passwords lab/wordlists/passwords.txt \
  --i-confirm-intrusive

python -m telepathiot acl --target broker-acl \
  --username sensor --password sensorpass \
  --i-confirm-intrusive
```

Fuzz only against a **disposable** broker instance. A crash is recorded as broker instability, not a generic socket error. Recreate the compose service afterward if needed.

```bash
python -m telepathiot fuzz --target broker-open --i-confirm-intrusive
# Optional resource test (not part of default fuzz):
python -m telepathiot fuzz --target broker-open --qos2-exhaustion --i-confirm-intrusive
```

Aggregate the latest session into HTML:

```bash
python -m telepathiot report --out sessions/report.html
```

CLI flags of note:

| Flag | Purpose |
| --- | --- |
| `--scope` | Path to allowlist (default `scope.json`) |
| `--rate-limit-ms` | Override default delay (scope default: 200) |
| `--skip-isolation-check` | Skip Docker `Internal` check — not for real sessions |
| `--i-confirm-intrusive` | Non-interactive confirm for lab automation |

## Agent integration

`telepathiot.agent_tools` exposes typed functions (`recon`, `topics`, `bruteforce`, …). An operator or LLM agent should call these wrappers rather than assembling raw MQTT or shell commands.

- Every call is allowlist-checked.
- MQTT topic names and payloads are returned under `untrusted_mqtt_content` / `data_inert` so they are treated as **data**, not instructions.
- Intrusive calls require `human_confirmed=True`.
- Credentials discovered on one target are not reused on another without explicit human authorization.

## Testing

```bash
python -m pytest tests/test_codec_and_scope.py tests/test_session.py tests/test_agent_gate.py -q
```

Unit tests cover CONNACK/AUTH parsing, scope deny, session flush, rate limiting, and the human gate. They do not require a live broker.

## Project layout

```text
telepathiot/          CLI, scope, session, MQTT codec, modules
lab/                  Docker Compose brokers + simulated devices
lab/wordlists/        Known-answer lists for broker-auth
scope.example.json    Template allowlist (copy to scope.json)
sessions/             Action logs and session JSON (local)
.findings.json        Extracted secrets (gitignored)
```

## Disclaimer

TelepathIoT is a laboratory assessment aid. Use it only on systems you own or are explicitly authorized to test, on an isolated network, with simulated devices unless a physical unit is separately in scope. The authors are not responsible for misuse or for damage to brokers that are not designed to tolerate malformed or high-rate CONNECT traffic.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).
