import json
import time
import statistics
import paho.mqtt.client as mqtt

BROKER = "10.222.86.179"
PORT = 1883
TOPIC = "iot/security/device01/telemetry"

timestamps = []
payload_sizes = []


def on_connect(client, userdata, flags, reason_code, properties):
    print("Connected to MQTT broker")
    print(f"Collecting communication features from: {TOPIC}")
    client.subscribe(TOPIC)


def on_message(client, userdata, msg):
    now = time.time()

    try:
        payload = json.loads(msg.payload.decode())
    except json.JSONDecodeError:
        print("Invalid JSON received")
        return

    timestamps.append(now)
    payload_sizes.append(len(msg.payload))

    # Keep the latest 20 messages for the rolling baseline
    if len(timestamps) > 20:
        timestamps.pop(0)
        payload_sizes.pop(0)

    print("\n========== COMMUNICATION FEATURES ==========")

    print(f"Device              : {payload.get('device_id')}")
    print(f"Payload size        : {len(msg.payload)} bytes")

    if len(timestamps) >= 2:
        intervals = [
            timestamps[i] - timestamps[i - 1]
            for i in range(1, len(timestamps))
        ]

        avg_interval = statistics.mean(intervals)
        message_rate = 60 / avg_interval if avg_interval > 0 else 0

        print(f"Average interval    : {avg_interval:.2f} seconds")
        print(f"Message rate        : {message_rate:.2f} messages/minute")

    else:
        print("Average interval    : collecting...")
        print("Message rate        : collecting...")

    avg_payload = statistics.mean(payload_sizes)

    print(f"Average payload     : {avg_payload:.2f} bytes")
    print(f"Messages collected  : {len(timestamps)}")
    print("============================================")


client = mqtt.Client(
    mqtt.CallbackAPIVersion.VERSION2,
    client_id="iot-feature-collector"
)

client.on_connect = on_connect
client.on_message = on_message

print("Starting IoT Communication Feature Collector...")
print(f"Broker: {BROKER}:{PORT}")

client.connect(BROKER, PORT, 60)
client.loop_forever()
