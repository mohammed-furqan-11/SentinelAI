import sys
import os

# Add the project root to Python's module search path
PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../..")
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from models.predictor import predict_threat


def analyze_event_with_ml(event):
    event_type = event.get("event_type")

    if event_type == "successful_login":
        failed_attempts = 0
        suspicious_login = 0
        risk_score = 10

    elif event_type == "failed_login":
        failed_attempts = 1
        suspicious_login = 0
        risk_score = 40

    elif event_type == "suspicious_login":
        failed_attempts = 1
        suspicious_login = 1
        risk_score = 70

    elif event_type == "brute_force_attempt":
        failed_attempts = 10
        suspicious_login = 0
        risk_score = 95

    else:
        failed_attempts = 0
        suspicious_login = 0
        risk_score = 0

    prediction = predict_threat(
        failed_attempts,
        suspicious_login,
        risk_score
    )

    return {
        "event": event,
        "prediction": prediction["prediction"],
        "threat_probability": prediction["threat_probability"]
    }


if __name__ == "__main__":
    sample_event = {
        "event_type": "suspicious_login",
        "source_ip": "192.168.1.101",
        "username": "admin"
    }

    result = analyze_event_with_ml(sample_event)

    print("--- ML Security Analysis ---")
    print(f"Event Type: {result['event']['event_type']}")
    print(f"Source IP: {result['event']['source_ip']}")
    print(f"Prediction: {result['prediction']}")
    print(
        f"Threat Probability: "
        f"{result['threat_probability']}%"
    )