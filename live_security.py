import json
import time
import os
import joblib
import numpy as np
import torch
import torch.nn as nn
import paho.mqtt.client as mqtt
import requests


BROKER = "localhost"
PORT = 1883
TOPIC = "iot/security/device01/telemetry"

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
GEMINI_MODEL = "gemini-3.5-flash-lite"

timestamps = []
payload_sizes = []

# Prevent repeated GenAI calls for the same suspicious event
last_genai_decision = None


# ==========================================
# DNN MODEL
# ==========================================

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
            nn.Sigmoid()
        )

    def forward(self, x):
        return self.network(x)


# ==========================================
# LOAD DNN + SCALER
# ==========================================

device = torch.device(
    "cuda" if torch.cuda.is_available() else "cpu"
)

model = IoTAnomalyDetector().to(device)

model.load_state_dict(
    torch.load(
        "iot_dnn_model.pth",
        map_location=device,
        weights_only=True
    )
)

model.eval()

scaler = joblib.load("iot_scaler.pkl")


# ==========================================
# RISK ENGINE
# ==========================================

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


# ==========================================
# GENAI SECURITY ANALYST
# ==========================================

def analyze_with_gemini(
    device_id,
    avg_interval,
    message_rate,
    avg_payload,
    anomaly_probability,
    risk_score,
    decision
):

    if not GEMINI_API_KEY:
        return "Gemini API key not found."


    prompt = f"""
You are an IoT cybersecurity analyst.

Analyze this security event using ONLY the supplied evidence.

Device: {device_id}

Communication behavior:
- Average message interval: {avg_interval:.2f} seconds
- Message rate: {message_rate:.2f} messages/minute
- Average payload size: {avg_payload:.2f} bytes

Machine-learning analysis:
- DNN anomaly probability: {anomaly_probability:.3f}

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

Important rules:
- Do not invent attack types.
- Do not claim C2, malware, botnet activity, firmware compromise,
  credential theft, or network intrusion unless explicit evidence is provided.
- Do not claim that an actual attack occurred.
- The suspicious behavior in this prototype is a controlled simulation.
- Clearly distinguish observed behavior from possible explanations.
- Base every conclusion only on the communication metrics,
  DNN probability, and risk score.
- Keep the response concise and suitable for a cybersecurity dashboard.
"""


    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"{GEMINI_MODEL}:generateContent"
        f"?key={GEMINI_API_KEY}"
    )


    request_body = {
        "contents": [
            {
                "parts": [
                    {
                        "text": prompt
                    }
                ]
            }
        ]
    }


    try:

        response = requests.post(
            url,
            headers={
                "Content-Type": "application/json"
            },
            json=request_body,
            timeout=15
        )


        if response.status_code != 200:
            return (
                f"Gemini API error "
                f"(HTTP {response.status_code})"
            )


        data = response.json()

        return (
            data["candidates"][0]
            ["content"]["parts"][0]["text"]
        )


    except requests.exceptions.Timeout:

        return "Gemini analysis timed out."


    except Exception as e:

        return f"Gemini analysis failed: {e}"


# ==========================================
# MQTT CONNECTION
# ==========================================

def on_connect(client, userdata, flags, reason_code, properties):

    print("Connected to MQTT broker")

    result, mid = client.subscribe(TOPIC)

    print(f"Subscribe result: {result}")
    print(f"Monitoring: {TOPIC}")
    print()


# ==========================================
# LIVE SECURITY ANALYSIS
# ==========================================

def on_message(client, userdata, msg):

    now = time.time()

    try:
        payload = json.loads(
            msg.payload.decode()
        )

    except json.JSONDecodeError:
        return


    timestamps.append(now)
    payload_sizes.append(len(msg.payload))


    # Rolling window
    if len(timestamps) > 20:

        timestamps.pop(0)
        payload_sizes.pop(0)


    # Need enough messages
    if len(timestamps) < 5:

        print(
            f"Collecting communication baseline "
            f"{len(timestamps)}/5..."
        )

        return


    # ======================================
    # FEATURE EXTRACTION
    # ======================================

    intervals = [
        timestamps[i] - timestamps[i - 1]
        for i in range(1, len(timestamps))
    ]

    avg_interval = np.mean(intervals)

    message_rate = (
        60 / avg_interval
        if avg_interval > 0
        else 0
    )

    avg_payload = np.mean(payload_sizes)


    # ======================================
    # DNN INFERENCE
    # ======================================

    features = np.array([
        [
            avg_interval,
            message_rate,
            avg_payload
        ]
    ])

    scaled_features = scaler.transform(
        features
    )

    tensor = torch.tensor(
        scaled_features,
        dtype=torch.float32
    ).to(device)


    with torch.no_grad():

        anomaly_probability = model(
            tensor
        ).item()


    # ======================================
    # RISK ENGINE
    # ======================================

    risk_score, decision = calculate_risk(
        anomaly_probability,
        message_rate
    )


    # ======================================
    # SECURITY OUTPUT
    # ======================================

    print()
    print("==========================================")
    print("       IoT SECURITY PLATFORM")
    print("==========================================")

    print(
        f"Device              : "
        f"{payload.get('device_id')}"
    )

    print(
        f"Communication mode  : "
        f"{payload.get('status')}"
    )

    print()
    print("COMMUNICATION BEHAVIOR")

    print(
        f"Average interval    : "
        f"{avg_interval:.3f} sec"
    )

    print(
        f"Message rate        : "
        f"{message_rate:.2f} msg/min"
    )

    print(
        f"Average payload     : "
        f"{avg_payload:.2f} bytes"
    )


    print()
    print("AI ANALYSIS")

    print(
        f"DNN probability     : "
        f"{anomaly_probability:.4f}"
    )


    print()
    print("RISK ENGINE")

    print(
        f"Risk score          : "
        f"{risk_score:.2f}/100"
    )

    print(
        f"Security decision   : "
        f"{decision}"
    )


    # ======================================
    # GENAI ANALYSIS
    # ======================================

    global last_genai_decision

    print()
    print("GENAI SECURITY ANALYST")
    print("------------------------------------------")

    if decision in ["SUSPICIOUS", "BLOCK"]:

        # Analyze only when entering a new suspicious state.
        if last_genai_decision not in ["SUSPICIOUS", "BLOCK"]:

            print("Analyzing security event with Gemini...")

            analysis = analyze_with_gemini(
                payload.get("device_id"),
                avg_interval,
                message_rate,
                avg_payload,
                anomaly_probability,
                risk_score,
                decision
            )

            print(analysis)

        else:
            print("Event already analyzed. Monitoring continues.")

    else:

        print("No GenAI investigation required.")

    # Remember current state.
    last_genai_decision = decision


    print("==========================================")


# ==========================================
# START
# ==========================================

client = mqtt.Client(
    mqtt.CallbackAPIVersion.VERSION2,
    client_id="live-security-platform"
)

client.on_connect = on_connect
client.on_message = on_message


print("==========================================")
print("      LIVE IoT SECURITY PLATFORM")
print("==========================================")

print(f"Compute device: {device}")

print("Gemini analyst: ENABLED")

print("Waiting for ESP32 traffic...")
print()


client.connect(
    BROKER,
    PORT,
    60
)

client.loop_forever()
