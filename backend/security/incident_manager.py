from datetime import datetime
import json
import os
import uuid


INCIDENT_LOG_FILE = "logs/incidents.json"


def generate_incident_id():
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    unique_id = uuid.uuid4().hex[:6].upper()

    return f"INC-{timestamp}-{unique_id}"


def load_incidents():
    incidents = []

    if not os.path.exists(INCIDENT_LOG_FILE):
        return incidents

    with open(INCIDENT_LOG_FILE, "r") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            try:
                incidents.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return incidents


def incident_exists(threat):
    incidents = load_incidents()

    source_ip = threat.get("source_ip")
    threat_name = threat.get("threat")

    for incident in incidents:
        if (
            incident.get("source_ip") == source_ip
            and incident.get("threat") == threat_name
            and incident.get("status") == "OPEN"
        ):
            return True

    return False


def create_incident(threat):
    if incident_exists(threat):
        return None

    incident = {
        "incident_id": generate_incident_id(),
        "timestamp": datetime.now().isoformat(),
        "source_ip": threat.get("source_ip"),
        "threat": threat.get("threat"),
        "risk_level": threat.get("risk_level"),
        "risk_score": threat.get("risk_score"),
        "status": "OPEN"
    }

    os.makedirs("logs", exist_ok=True)

    with open(INCIDENT_LOG_FILE, "a") as file:
        file.write(json.dumps(incident) + "\n")

    return incident


def get_all_incidents():
    return load_incidents()


if __name__ == "__main__":

    sample_threat = {
        "source_ip": "192.168.1.250",
        "threat": "Suspicious login",
        "risk_level": "HIGH",
        "risk_score": 85
    }

    incident = create_incident(sample_threat)

    if incident:
        print("--- Security Incident ---")
        print(f"Incident ID: {incident['incident_id']}")
        print(f"Source IP: {incident['source_ip']}")
        print(f"Threat: {incident['threat']}")
        print(f"Risk Level: {incident['risk_level']}")
        print(f"Risk Score: {incident['risk_score']}")
        print(f"Status: {incident['status']}")
    else:
        print("Incident already exists.")