
import pandas as pd
import torch
import torch.nn as nn

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report

import joblib


# -----------------------------
# Load dataset
# -----------------------------

df = pd.read_csv("iot_behavior_dataset.csv")

X = df[
    [
        "avg_interval",
        "message_rate",
        "payload_size"
    ]
].values

y = df["label"].values


# -----------------------------
# Train/test split
# -----------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)


# -----------------------------
# Feature scaling
# -----------------------------

scaler = StandardScaler()

X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)


# Convert to PyTorch tensors
X_train = torch.tensor(X_train, dtype=torch.float32)
y_train = torch.tensor(y_train, dtype=torch.float32).reshape(-1, 1)

X_test = torch.tensor(X_test, dtype=torch.float32)
y_test = torch.tensor(y_test, dtype=torch.float32).reshape(-1, 1)


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
# Device
# -----------------------------

device = torch.device(
    "cuda" if torch.cuda.is_available() else "cpu"
)

print("Training device:", device)

model = IoTAnomalyDetector().to(device)

X_train = X_train.to(device)
y_train = y_train.to(device)

X_test = X_test.to(device)
y_test = y_test.to(device)


# -----------------------------
# Training
# -----------------------------

criterion = nn.BCELoss()

optimizer = torch.optim.Adam(
    model.parameters(),
    lr=0.001
)


epochs = 100

for epoch in range(epochs):

    model.train()

    optimizer.zero_grad()

    output = model(X_train)

    loss = criterion(output, y_train)

    loss.backward()

    optimizer.step()

    if (epoch + 1) % 10 == 0:

        print(
            f"Epoch [{epoch + 1}/{epochs}] "
            f"Loss: {loss.item():.6f}"
        )


# -----------------------------
# Evaluation
# -----------------------------

model.eval()

with torch.no_grad():

    predictions = model(X_test)

    predicted_labels = (
        predictions >= 0.5
    ).int().cpu().numpy().flatten()

    actual_labels = (
        y_test.cpu().numpy().flatten().astype(int)
    )


accuracy = accuracy_score(
    actual_labels,
    predicted_labels
)


print()
print("==============================")
print("DNN IoT ANOMALY DETECTOR")
print("==============================")

print(f"Test Accuracy: {accuracy * 100:.2f}%")

print()
print("Classification Report:")

print(
    classification_report(
        actual_labels,
        predicted_labels,
        target_names=[
            "Normal",
            "Suspicious"
        ]
    )
)


# -----------------------------
# Save model
# -----------------------------

torch.save(
    model.state_dict(),
    "iot_dnn_model.pth"
)

joblib.dump(
    scaler,
    "iot_scaler.pkl"
)


print("Model saved: iot_dnn_model.pth")
print("Scaler saved: iot_scaler.pkl")
