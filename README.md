TelepathIoT
===========

Isolated-lab MQTT broker assessment toolkit. It talks **only** to hosts:ports listed in `scope.json`. Simulated devices only. No production paths.

Hard rules
----------

1. Isolated network only. Lab brokers live on the Docker network `telepathiot-lab` with `internal: true`. Run `telepathiot verify-env` (or `docker network inspect telepathiot-lab`) **before every session**.
2. No real device firmware unless you have separate, explicit authorization. The compose stack ships `sim-devices` only.
3. Intrusive modules (bruteforce, acl, fuzz) are rate-limited (default **200ms**). Do not disable this to "go faster" — unthrottled CONNECT storms can crash small brokers and teach you nothing about auth.
4. Snapshot broker data dirs before retained/ACL runs; restore after. `telepathiot snapshot --name pre` / `telepathiot restore --name pre`.
5. Ctrl+C flushes `sessions/<id>.session.json` (kill switch).
6. Extracted passwords/tokens go to `.findings.json` (gitignored). They are not printed in full.
7. Every send is recorded in the session action log, not just findings.

MQTT 3.1.1 vs 5.0 CONNACK are parsed separately. An AUTH packet is treated as enhanced authentication: bruteforce is marked **out of scope**, not "not vulnerable". Client IDs are random per connection. Publish defaults to `retain=False`. QoS 2 partial-handshake fuzz is **opt-in** (`--qos2-exhaustion`). `$SYS` is its own recon check.

Lab
---

```text
cd lab
docker compose pull
docker compose up --build -d
cd ..
copy scope.example.json scope.json   # Windows
# cp scope.example.json scope.json  # Unix
python -m pip install -e ".[dev]"
python -m telepathiot verify-env
```

| Container    | Host port      | Known answer                                      |
|--------------|----------------|---------------------------------------------------|
| broker-open  | 127.0.0.1:1883 | anonymous = true, `$SYS` leak, sim topics         |
| broker-auth  | 127.0.0.1:1884 | anonymous = false; user `labuser` / `labpass`     |
| broker-acl   | 127.0.0.1:1885 | sensor may not subscribe to `#` or `admin/#`      |
| broker-tls   | 127.0.0.1:8883 | TLS; plaintext still on 1886 (deliberate misconfig)|
| sim-devices  | (internal)     | retained honeypot `admin/token` on broker-open    |

Ground truth before the tool: `mosquitto_sub` / `mosquitto_pub` against each listener.

Phases
------

```text
python -m telepathiot recon --target broker-open
python -m telepathiot recon --target broker-auth
python -m telepathiot recon --target broker-acl
python -m telepathiot recon --target broker-tls

python -m telepathiot topics --target broker-open
python -m telepathiot topics --target broker-acl

python -m telepathiot snapshot --name pre-brute --lab-dir lab
python -m telepathiot bruteforce --target broker-auth --users lab/wordlists/users.txt --passwords lab/wordlists/passwords.txt --i-confirm-intrusive
python -m telepathiot acl --target broker-acl --username sensor --password sensorpass --i-confirm-intrusive
python -m telepathiot tls --target broker-tls
python -m telepathiot fuzz --target broker-open --i-confirm-intrusive
python -m telepathiot report --out sessions/report.html
```

Fuzz against a broker you are willing to lose; compose recreate if it dies. Instability is logged as `broker instability`, not a generic socket error.

Agent guardrails
----------------

`telepathiot/agent_tools.py` exposes typed functions. Each call hits `scope.json` first. Intrusive modules require `human_confirmed=True`. MQTT payloads are returned under `untrusted_mqtt_content` / `data_inert` so they are **data**, not instructions. Do not auto-replay credentials from broker A onto broker B.

Tests
-----

```text
python -m pytest
```
