import os
from google import genai

client = genai.Client(
    api_key=os.environ["GEMINI_API_KEY"]
)

def analyze_incident(
    device_id,
    avg_interval,
    message_rate,
    payload_size,
    dnn_probability,
    risk_score,
    decision
):
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

    response = client.models.generate_content(
        model="gemini-3.5-flash-lite",
        contents=prompt
    )

    return response.text


if __name__ == "__main__":
    result = analyze_incident(
        device_id="ESP32-Device01",
        avg_interval=0.20,
        message_rate=294.49,
        payload_size=85,
        dnn_probability=0.527,
        risk_score=66.89,
        decision="SUSPICIOUS"
    )

    print("\n==========================================")
    print("        GENAI SECURITY ANALYST")
    print("==========================================")
    print(result)
    print("==========================================")
