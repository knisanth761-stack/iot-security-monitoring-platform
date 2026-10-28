#include <WiFi.h>
#include <PubSubClient.h>

const char* WIFI_SSID = "YOUR_WIFI_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";

const char* MQTT_BROKER = "10.222.86.179";
const int MQTT_PORT = 1883;
const char* MQTT_TOPIC = "iot/security/device01/telemetry";
const char* MQTT_STATUS_TOPIC = "iot/security/device01/status";

WiFiClient espClient;
PubSubClient mqttClient(espClient);

bool suspiciousMode = false;

unsigned long modeStartTime = 0;
const unsigned long MODE_DURATION = 30000;

unsigned long lastNormalPublish = 0;
const unsigned long NORMAL_INTERVAL = 5000;

void connectWiFi() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  Serial.print("Connecting to Wi-Fi");

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println();
  Serial.println("Wi-Fi connected!");
  Serial.print("ESP32 IP: ");
  Serial.println(WiFi.localIP());
}

void connectMQTT() {
  while (!mqttClient.connected()) {
    Serial.print("Connecting to MQTT...");

    String clientId = "ESP32-Device01";

    if (mqttClient.connect(clientId.c_str(), MQTT_STATUS_TOPIC, 0, true, "offline")) {
      Serial.println("CONNECTED");
    } else {
      Serial.print("FAILED, state=");
      Serial.println(mqttClient.state());
      delay(2000);
    }
  }
}

void publishTelemetry() {
  String payload = "{";
  payload += "\"device_id\":\"ESP32-Device01\",";
  payload += "\"temperature\":28.5,";
  payload += "\"humidity\":65,";
  payload += "\"status\":\"";

  payload += suspiciousMode ? "suspicious" : "normal";

  payload += "\"}";

  mqttClient.publish(MQTT_TOPIC, payload.c_str());

  Serial.println("MQTT message published:");
  Serial.println(payload);
}

void updateMode() {
  unsigned long now = millis();

  if (now - modeStartTime >= MODE_DURATION) {
    suspiciousMode = !suspiciousMode;
    modeStartTime = now;

    Serial.println();
    Serial.println("================================");

    if (suspiciousMode) {
      Serial.println(">>> SUSPICIOUS MODE STARTED <<<");
    } else {
      Serial.println(">>> NORMAL MODE STARTED <<<");
    }

    Serial.println("================================");
    Serial.println();
  }
}

void setup() {
  mqttClient.setKeepAlive(5);
  Serial.begin(115200);
  delay(1000);

  Serial.println();
  Serial.println("================================");
  Serial.println("   ESP32 IoT SECURITY PLATFORM");
  Serial.println("================================");
  Serial.println("NORMAL     -> 30 seconds");
  Serial.println("SUSPICIOUS -> 30 seconds");
  Serial.println("================================");

  connectWiFi();

  mqttClient.setServer(MQTT_BROKER, MQTT_PORT);

  modeStartTime = millis();
  suspiciousMode = false;
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) {
    connectWiFi();
  }

  if (!mqttClient.connected()) {
    connectMQTT();
  }

  mqttClient.loop();
  updateMode();

  unsigned long now = millis();

  if (!suspiciousMode) {
    if (now - lastNormalPublish >= NORMAL_INTERVAL) {
      lastNormalPublish = now;
      publishTelemetry();
    }
  } else {
    Serial.println("!!! SUSPICIOUS TRAFFIC !!!");

    for (int i = 0; i < 10; i++) {
      publishTelemetry();
      delay(100);
    }

    delay(1000);
  }
}
