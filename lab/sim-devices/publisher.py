"""Simulated sensors only — no real-device firmware."""

from __future__ import annotations

import json
import os
import time
import uuid

import paho.mqtt.client as mqtt

HOST = os.environ.get("MQTT_HOST", "broker-open")
PORT = int(os.environ.get("MQTT_PORT", "1883"))
HONEYPOT_TOPIC = "admin/token"
HONEYPOT_PAYLOAD = "lab-only-fake-token-do-not-reuse"


def main() -> None:
    cid = f"sim-{uuid.uuid4().hex[:8]}"
    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2, client_id=cid)
    client.connect(HOST, PORT, keepalive=30)
    client.loop_start()
    client.publish(HONEYPOT_TOPIC, HONEYPOT_PAYLOAD, qos=0, retain=True)
    n = 0
    try:
        while True:
            n += 1
            client.publish(
                "sensors/device1/temp",
                json.dumps({"celsius": 21.5 + (n % 5) * 0.1, "n": n}),
                qos=0,
                retain=False,
            )
            client.publish(
                "sensors/device1/gps",
                json.dumps({"lat": 25.2048, "lon": 55.2708, "n": n}),
                qos=0,
                retain=False,
            )
            time.sleep(2)
    except KeyboardInterrupt:
        pass
    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()
