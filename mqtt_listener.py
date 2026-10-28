import json
import time
import paho.mqtt.client as mqtt

BROKER = "10.222.86.179"
PORT = 1883
TOPIC = "iot/security/device01/telemetry"


def on_connect(client, userdata, flags, reason_code, properties):
    print("Connected to MQTT broker")
    print(f"Listening on: {TOPIC}")
    client.subscribe(TOPIC)


def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())

        print("\n--- IoT Telemetry Received ---")
        print(f"Device      : {payload.get('device_id')}")
        print(f"Temperature : {payload.get('temperature')}")
        print(f"Humidity    : {payload.get('humidity')}")
        print(f"Status      : {payload.get('status')}")
        print(f"Payload size: {len(msg.payload)} bytes")
        print(f"Timestamp   : {time.time()}")

    except json.JSONDecodeError:
        print("Invalid JSON received:", msg.payload.decode())


client = mqtt.Client(
    mqtt.CallbackAPIVersion.VERSION2,
    client_id="security-platform-listener"
)

client.on_connect = on_connect
client.on_message = on_message

print("Starting IoT Security MQTT Listener...")
print(f"Broker: {BROKER}:{PORT}")

client.connect(BROKER, PORT, 60)
client.loop_forever()
