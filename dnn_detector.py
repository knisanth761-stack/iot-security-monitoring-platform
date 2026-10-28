import torch
import torch.nn as nn
import joblib
import numpy as np


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
# Load model
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


# -----------------------------
# Load scaler
# -----------------------------

scaler = joblib.load("iot_scaler.pkl")


# -----------------------------
# Detection function
# -----------------------------

def detect(avg_interval, message_rate, payload_size):

    features = np.array([
        [avg_interval, message_rate, payload_size]
    ])

    features = scaler.transform(features)

    tensor = torch.tensor(
        features,
        dtype=torch.float32
    ).to(device)

    with torch.no_grad():
        probability = model(tensor).item()

    if probability >= 0.5:
        label = "SUSPICIOUS"
    else:
        label = "NORMAL"

    print()
    print("==============================")
    print("DNN IoT BEHAVIOR DETECTOR")
    print("==============================")
    print(f"Average interval : {avg_interval:.2f} sec")
    print(f"Message rate     : {message_rate:.2f} msg/min")
    print(f"Payload size     : {payload_size:.2f} bytes")
    print(f"Anomaly probability: {probability:.4f}")
    print(f"Detection        : {label}")
    print("==============================")


# -----------------------------
# Test with current ESP32
# -----------------------------

detect(
    avg_interval=5.0,
    message_rate=12.0,
    payload_size=81
)

detect(
    avg_interval=0.2,
    message_rate=300.0,
    payload_size=85
)
