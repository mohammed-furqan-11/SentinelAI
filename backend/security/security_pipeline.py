from backend.security.event_generator import generate_security_event
from backend.security.threat_detector import detect_threat
from backend.security.ml_detector import analyze_event_with_ml
from backend.security.risk_engine import calculate_final_risk
from backend.security.response_engine import (
    respond_to_threat,
    save_response,
    response_already_exists
)
from backend.database import save_security_event

import json
import os


SUPPORTED_ML_EVENT_TYPES = {
    "successful_login",
    "failed_login",
    "suspicious_login",
    "brute_force_attempt"
}


def process_security_event(event=None):
    if event is None:
        event = generate_security_event()

    rule_analysis = detect_threat(event)

    if event.get("event_type") in SUPPORTED_ML_EVENT_TYPES:
        ml_analysis = analyze_event_with_ml(event)
    else:
        ml_analysis = {
            "prediction": 0,
            "threat_probability": 0.0
        }

    final_risk = calculate_final_risk(
        rule_analysis["risk_score"],
        ml_analysis["threat_probability"]
    )

    event["risk_level"] = final_risk["risk_level"]
    event["risk_score"] = final_risk["final_risk_score"]

    save_security_event(event)

    threat = {
        "source_ip": event.get("source_ip"),
        "threat": event.get("event_type"),
        "risk_level": final_risk["risk_level"],
        "risk_score": final_risk["final_risk_score"]
    }

    response = respond_to_threat(threat)

    return {
        "event": event,
        "rule_analysis": rule_analysis,
        "ml_analysis": ml_analysis,
        "final_risk": final_risk,
        "response": response
    }


def save_threat_analysis(analysis):
    log_file = "logs/threat_analysis.json"

    os.makedirs("logs", exist_ok=True)

    with open(log_file, "a") as file:
        file.write(json.dumps(analysis) + "\n")


if __name__ == "__main__":
    for _ in range(10):
        result = process_security_event()

        save_threat_analysis(result)

        event = result["event"]
        rule_analysis = result["rule_analysis"]
        ml_analysis = result["ml_analysis"]
        final_risk = result["final_risk"]
        response = result["response"]

        print("\n--- Security Analysis ---")
        print(f"Event Type: {event['event_type']}")
        print(f"Source IP: {event['source_ip']}")
        print(f"Username: {event.get('username')}")

        print("\nRule-Based Detection:")
        print(f"Risk Level: {rule_analysis['risk_level']}")
        print(f"Risk Score: {rule_analysis['risk_score']}")

        print("\nML Detection:")
        print(f"Prediction: {ml_analysis['prediction']}")
        print(
            f"Threat Probability: "
            f"{ml_analysis['threat_probability']}%"
        )

        print("\nFinal Risk:")
        print(f"Risk Level: {final_risk['risk_level']}")
        print(f"Risk Score: {final_risk['final_risk_score']}")

        print("\nAutonomous Response:")

        if response_already_exists(
            response["source_ip"],
            response["action"]
        ):
            print("Threat already handled.")
            print(f"Action: {response['action']}")

        else:
            save_response(response)
            print("New response executed.")
            print(f"Action: {response['action']}")