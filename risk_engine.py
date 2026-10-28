def calculate_risk(anomaly_probability, message_rate):
    """
    Convert DNN anomaly probability and communication rate
    into a simple security risk score.
    """

    # DNN contribution: 0–70
    dnn_risk = anomaly_probability * 70

    # Communication-rate contribution: 0–30
    if message_rate <= 20:
        rate_risk = 0
    elif message_rate <= 100:
        rate_risk = 10
    elif message_rate <= 200:
        rate_risk = 20
    else:
        rate_risk = 30

    risk_score = dnn_risk + rate_risk

    # Security decision
    if risk_score < 25:
        decision = "NORMAL"
    elif risk_score < 40:
        decision = "REVIEW"
    elif risk_score < 70:
        decision = "SUSPICIOUS"
    else:
        decision = "BLOCK"

    return risk_score, decision


# --------------------------------
# Test with normal behavior
# --------------------------------

normal_probability = 0.0746
normal_rate = 12

score, decision = calculate_risk(
    normal_probability,
    normal_rate
)

print("================================")
print("IoT SECURITY RISK ENGINE")
print("================================")
print("NORMAL TRAFFIC")
print(f"DNN probability : {normal_probability:.4f}")
print(f"Message rate    : {normal_rate:.2f} msg/min")
print(f"Risk score      : {score:.2f}/100")
print(f"Decision        : {decision}")


# --------------------------------
# Test with suspicious behavior
# --------------------------------

suspicious_probability = 0.5270
suspicious_rate = 294.49

score, decision = calculate_risk(
    suspicious_probability,
    suspicious_rate
)

print()
print("SUSPICIOUS TRAFFIC")
print(f"DNN probability : {suspicious_probability:.4f}")
print(f"Message rate    : {suspicious_rate:.2f} msg/min")
print(f"Risk score      : {score:.2f}/100")
print(f"Decision        : {decision}")
print("================================")
