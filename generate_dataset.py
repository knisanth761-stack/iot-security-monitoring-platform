import csv
import random

OUTPUT = "iot_behavior_dataset.csv"

rows = []

# Normal IoT communication
for _ in range(500):
    avg_interval = random.uniform(4.5, 5.5)
    message_rate = 60 / avg_interval
    payload_size = random.uniform(78, 84)

    rows.append([
        avg_interval,
        message_rate,
        payload_size,
        0
    ])

# Suspicious communication
for _ in range(500):
    avg_interval = random.uniform(0.10, 0.30)
    message_rate = 60 / avg_interval
    payload_size = random.uniform(82, 100)

    rows.append([
        avg_interval,
        message_rate,
        payload_size,
        1
    ])

random.shuffle(rows)

with open(OUTPUT, "w", newline="") as f:
    writer = csv.writer(f)

    writer.writerow([
        "avg_interval",
        "message_rate",
        "payload_size",
        "label"
    ])

    writer.writerows(rows)

print(f"Dataset created: {OUTPUT}")
print(f"Total samples: {len(rows)}")
print("Normal samples: 500")
print("Suspicious samples: 500")
