from collections import defaultdict

from log_reader import read_security_events
from incident_manager import create_incident
from response_engine import respond_to_threat, save_response


def detect_brute_force(events, threshold=5):
    failed_attempts = defaultdict(int)

    for event in events:
        if event.get("event_type") == "failed_login":
            source_ip = event.get("source_ip")

            if source_ip:
                failed_attempts[source_ip] += 1

    threats = []

    for ip, count in failed_attempts.items():
        if count >= threshold:
            threats.append({
                "source_ip": ip,
                "failed_attempts": count,
                "risk_level": "CRITICAL",
                "risk_score": 95,
                "threat": "Brute-force attack"
            })

    return threats


def detect_suspicious_logins(events):
    threats = []

    for event in events:
        if event.get("event_type") == "suspicious_login":
            threats.append({
                "source_ip": event.get("source_ip"),
                "username": event.get("username"),
                "threat": "Suspicious login",
                "risk_level": "HIGH",
                "risk_score": 70
            })

    return threats


def process_threat(threat):

    print("\n--- Threat Detection ---")
    print(f"Source IP: {threat['source_ip']}")
    print(f"Threat: {threat['threat']}")
    print(f"Risk Level: {threat['risk_level']}")
    print(f"Risk Score: {threat['risk_score']}")

    incident = create_incident(threat)

    print("\n--- Security Incident ---")

    if incident:
        print(f"Incident ID: {incident['incident_id']}")
        print(f"Status: {incident['status']}")

        response = respond_to_threat(threat)

        print("\n--- Autonomous Response ---")

        if response.get("action") != "NO_ACTION":
            save_response(response)
            print("New response executed.")
        else:
            print("No response required.")

        print(f"Action: {response['action']}")

    else:
        print("Incident already exists.")

        print("\n--- Autonomous Response ---")
        print("Threat already handled.")

        existing_response = respond_to_threat(threat)
        print(f"Action: {existing_response['action']}")


if __name__ == "__main__":

    events = read_security_events()

    brute_force_threats = detect_brute_force(events)
    suspicious_login_threats = detect_suspicious_logins(events)

    threats = brute_force_threats + suspicious_login_threats

    print(f"Total events analyzed: {len(events)}")
    print(f"Threats detected: {len(threats)}")

    for threat in threats:
        process_threat(threat)