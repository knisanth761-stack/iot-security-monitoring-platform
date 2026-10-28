from datetime import datetime
import json
import time
import threading
import os
import requests

import joblib
import numpy as np
import torch
import torch.nn as nn
import paho.mqtt.client as mqtt
from flask import Flask, jsonify
from flask_cors import CORS

BROKER = "localhost"
PORT = 1883
TOPIC = "iot/security/device01/telemetry"
STATUS_TOPIC = "iot/security/device01/status"

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
GEMINI_MODEL = "gemini-3.5-flash-lite"

last_genai_decision = None

app = Flask(__name__)
CORS(app)

state = {
    "device_id": "ESP32-Device01",
    "mode": "WAITING",
    "avg_interval": 0,
    "message_rate": 0,
    "payload_size": 0,
    "anomaly_probability": 0,
    "risk_score": 0,
    "decision": "WAITING",
    "genai_analysis": "",
    "mqtt_connected": False,
    "updated_at": None,
}

timestamps = []
payload_sizes = []


def device_watchdog():
    while True:
        time.sleep(1)

        last = state.get("last_seen")

        if last is None:
            continue

        try:
            age = (
                datetime.now()
                - datetime.fromisoformat(last)
            ).total_seconds()

            if age > 8:
                if state["mqtt_connected"]:
                    print(
                        f"ESP32 OFFLINE: no telemetry/status for {age:.1f}s"
                    )

                state["mqtt_connected"] = False

        except Exception:
            pass


threading.Thread(
    target=device_watchdog,
    daemon=True,
).start()


class IoTAnomalyDetector(nn.Module):
    def __init__(self):
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(3, 32),
            nn.ReLU(),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, 8),
            nn.ReLU(),
            nn.Linear(8, 1),
            nn.Sigmoid(),
        )

    def forward(self, x):
        return self.network(x)


device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

model = IoTAnomalyDetector().to(device)
model.load_state_dict(
    torch.load(
        "iot_dnn_model.pth",
        map_location=device,
        weights_only=True,
    )
)
model.eval()

scaler = joblib.load("iot_scaler.pkl")



def analyze_with_gemini(
    device_id,
    avg_interval,
    message_rate,
    payload_size,
    dnn_probability,
    risk_score,
    decision,
):
    if not GEMINI_API_KEY:
        return "Gemini API key not configured."

    prompt = f"""
You are an IoT cybersecurity analyst.

Analyze this security event using ONLY the supplied evidence.

Device: {device_id}

Communication behavior:
- Average message interval: {avg_interval:.2f} seconds
- Message rate: {message_rate:.2f} messages/minute
- Average payload size: {payload_size:.2f} bytes

Machine-learning analysis:
- DNN anomaly probability: {dnn_probability:.3f}

Risk engine:
- Risk score: {risk_score:.2f}/100
- Security decision: {decision}

Provide exactly these four sections:

1. Event Explanation
Briefly explain what was detected.

2. Main Behavioral Indicators
List the important observed communication metrics.

3. Security Interpretation
Interpret the behavior ONLY from the supplied evidence.

4. Recommended Defensive Action
Give ONE practical defensive action.

Rules:
- Do not invent attack types.
- Do not claim malware, C2, botnet activity, firmware compromise,
  credential theft, or network intrusion.
- Do not claim an actual attack occurred.
- This is a controlled suspicious-behavior simulation.
- Base conclusions only on the supplied metrics and AI/risk results.
- Keep the response concise and dashboard-ready.
"""

    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"{GEMINI_MODEL}:generateContent"
    )

    body = {
        "contents": [
            {
                "parts": [
                    {"text": prompt}
                ]
            }
        ]
    }

    try:
        response = requests.post(
            url,
            headers={
                "Content-Type": "application/json",
                "x-goog-api-key": GEMINI_API_KEY,
            },
            json=body,
            timeout=15,
        )

        if response.status_code != 200:
            print("GEMINI ERROR:", response.text[:1500])
            return f"Gemini API error: HTTP {response.status_code}"

        data = response.json()

        text = data["candidates"][0]["content"]["parts"][0]["text"]

        print("Gemini analysis completed.")

        return text

    except requests.Timeout:
        return "Gemini analysis timed out."

    except Exception as e:
        return f"Gemini analysis unavailable: {e}"

def calculate_risk(anomaly_probability, message_rate):
    dnn_risk = anomaly_probability * 70

    if message_rate <= 20:
        rate_risk = 0
    elif message_rate <= 100:
        rate_risk = 10
    elif message_rate <= 200:
        rate_risk = 20
    else:
        rate_risk = 30

    risk_score = dnn_risk + rate_risk

    if risk_score < 25:
        decision = "NORMAL"
    elif risk_score < 40:
        decision = "REVIEW"
    elif risk_score < 70:
        decision = "SUSPICIOUS"
    else:
        decision = "BLOCK"

    return risk_score, decision


def on_connect(client, userdata, flags, reason_code, properties):
    print("Dashboard API connected to MQTT")

    client.subscribe(TOPIC)
    client.subscribe(STATUS_TOPIC)

    print(f"Monitoring: {TOPIC}")
    print(f"Monitoring: {STATUS_TOPIC}")


def on_disconnect(client, userdata, disconnect_flags, reason_code, properties):
    print("Dashboard API disconnected from MQTT broker")


def on_message(client, userdata, msg):
    global last_seen, mqtt_connected
    last_seen = time.time()
    mqtt_connected = True
    global last_device_mode
    MQTT_STATUS_TOPIC_HANDLED = True

    if msg.topic == STATUS_TOPIC:
        status = msg.payload.decode().strip().lower()

        if status == "online":
            state["mqtt_connected"] = True
            state["last_seen"] = datetime.now().isoformat()
            print("ESP32 STATUS: ONLINE")

        elif status == "offline":
            state["mqtt_connected"] = False
            print("ESP32 STATUS: OFFLINE")

        return
    now = time.time()

    try:
        payload = json.loads(msg.payload.decode())
    except json.JSONDecodeError:
        return

    timestamps.append(now)
    payload_sizes.append(len(msg.payload))
    state["last_seen"] = datetime.now().isoformat()
    state["mqtt_connected"] = True

    if len(timestamps) > 20:
        timestamps.pop(0)
        payload_sizes.pop(0)

    if len(timestamps) < 5:
        state["device_id"] = payload.get(
            "device_id",
            "ESP32-Device01",
        )
        state["mode"] = payload.get("status", "normal").upper()
        return

    intervals = [
        timestamps[i] - timestamps[i - 1]
        for i in range(1, len(timestamps))
    ]

    avg_interval = float(np.mean(intervals))

    message_rate = (
        60 / avg_interval
        if avg_interval > 0
        else 0
    )

    avg_payload = float(np.mean(payload_sizes))

    features = np.array(
        [[avg_interval, message_rate, avg_payload]]
    )

    scaled_features = scaler.transform(features)

    tensor = torch.tensor(
        scaled_features,
        dtype=torch.float32,
    ).to(device)

    with torch.no_grad():
        anomaly_probability = model(tensor).item()

    risk_score, decision = calculate_risk(
        anomaly_probability,
        message_rate,
    )

    state.update(
        {
            "device_id": payload.get(
                "device_id",
                "ESP32-Device01",
            ),
            "mode": payload.get(
                "status",
                "normal",
            ).upper(),
            "avg_interval": avg_interval,
            "message_rate": message_rate,
            "payload_size": avg_payload,
            "anomaly_probability": anomaly_probability,
            "risk_score": risk_score,
            "decision": decision,
            "updated_at": time.time(),
        }
    )

    global last_genai_decision

    # Generate a fresh Gemini explanation whenever the security
    # state enters SUSPICIOUS/BLOCK. The explanation uses the
    # exact rolling-window values currently shown on the dashboard.
    if decision in ["SUSPICIOUS", "BLOCK"]:
        if last_genai_decision not in ["SUSPICIOUS", "BLOCK"]:
            print("Running Gemini security analysis...")

            analysis = analyze_with_gemini(
                payload.get(
                    "device_id",
                    "ESP32-Device01",
                ),
                avg_interval,
                message_rate,
                avg_payload,
                anomaly_probability,
                risk_score,
                decision,
            )

            state["genai_analysis"] = analysis

            print("Gemini analysis completed.")

    elif decision == "NORMAL":
        # Clear stale incident analysis after returning to normal.
        state["genai_analysis"] = ""

    last_genai_decision = decision

    print(
        f"{state['mode']:10} | "
        f"{message_rate:7.2f} msg/min | "
        f"DNN {anomaly_probability:.3f} | "
        f"Risk {risk_score:5.1f} | "
        f"{decision}"
    )


@app.get("/api/state")
def get_state():
    return jsonify(state)


@app.get("/api/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "mqtt_connected": state["mqtt_connected"],
            "model_device": str(device),
        }
    )


def mqtt_worker():
    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id="iot-dashboard-api",
    )

    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_message = on_message

    print("Connecting dashboard API to MQTT...")

    client.connect(BROKER, PORT, 60)

    client.loop_forever()


if __name__ == "__main__":
    mqtt_thread = threading.Thread(
        target=mqtt_worker,
        daemon=True,
    )

    mqtt_thread.start()

    print()
    print("==========================================")
    print("       IOT SECURITY DASHBOARD API")
    print("==========================================")
    print("API: http://localhost:5000")
    print("State: http://localhost:5000/api/state")
    print("Health: http://localhost:5000/api/health")
    print("==========================================")
    print()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False,
    )
