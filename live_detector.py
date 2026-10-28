import json
import time
import joblib
import numpy as np
import torch
import torch.nn as nn
import paho.mqtt.client as mqtt


BROKER = "10.222.86.179"
PORT = 1883
TOPIC = "iot/security/device01/telemetry"

timestamps = []
payload_sizes = []


# -----------------------------
# DNN model
# -----------------------------

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


# -----------------------------
# Load trained DNN
# -----------------------------

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

print("======================================")
print("LIVE IoT DNN THREAT DETECTOR")
print("======================================")
print(f"Device: {device}")
print(f"Listening: {TOPIC}")
print("Waiting for ESP32 traffic...")
print()


# -----------------------------
# MQTT connection
# -----------------------------

def on_connect(client, userdata, flags, reason_code, properties):

    print("Connected to MQTT broker")
    client.subscribe(TOPIC)


# -----------------------------
# Analyze incoming traffic
# -----------------------------

def on_message(client, userdata, msg):

    now = time.time()

    try:
        payload = json.loads(msg.payload.decode())
    except json.JSONDecodeError:
        return

    timestamps.append(now)
    payload_sizes.append(len(msg.payload))

    # Keep rolling window
    if len(timestamps) > 20:
        timestamps.pop(0)
        payload_sizes.pop(0)

    if len(timestamps) < 5:
        print(
            f"Collecting baseline... "
            f"{len(timestamps)}/5 messages"
        )
        return

    # Calculate communication behavior
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

    # -----------------------------
    # Prepare DNN input
    # -----------------------------

    features = np.array([
        [
            avg_interval,
            message_rate,
            avg_payload
        ]
    ])

    scaled_features = scaler.transform(features)

    tensor = torch.tensor(
        scaled_features,
        dtype=torch.float32
    ).to(device)

    # -----------------------------
    # DNN prediction
    # -----------------------------

    with torch.no_grad():

        probability = model(tensor).item()

    if probability >= 0.5:
        detection = "SUSPICIOUS"
    else:
        detection = "NORMAL"

    print()
    print("======================================")
    print("LIVE IoT BEHAVIOR ANALYSIS")
    print("======================================")

    print(f"Device          : {payload.get('device_id')}")
    print(f"Avg interval    : {avg_interval:.3f} sec")
    print(f"Message rate    : {message_rate:.2f} msg/min")
    print(f"Avg payload     : {avg_payload:.2f} bytes")

    print()
    print(
        f"DNN probability: {probability:.4f}"
    )

    print(
        f"Detection       : {detection}"
    )

    print("======================================")


# -----------------------------
# Start MQTT client
# -----------------------------

client = mqtt.Client(
    mqtt.CallbackAPIVersion.VERSION2,
    client_id="live-dnn-detector"
)

client.on_connect = on_connect
client.on_message = on_message

client.connect(BROKER, PORT, 60)

client.loop_forever()
