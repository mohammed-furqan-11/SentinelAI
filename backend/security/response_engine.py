from datetime import datetime
import json
import os


def respond_to_threat(threat):
    risk_level = threat.get("risk_level")
    source_ip = threat.get("source_ip")

    if risk_level == "CRITICAL":
        action = "BLOCK_IP"

    elif risk_level == "HIGH":
        action = "ALERT_ADMIN"

    elif risk_level == "MEDIUM":
        action = "MONITOR"

    else:
        action = "NO_ACTION"

    response = {
        "timestamp": datetime.now().isoformat(),
        "source_ip": source_ip,
        "risk_level": risk_level,
        "action": action
    }

    return response


def response_already_exists(source_ip, action):
    log_file = "logs/response_actions.json"

    if not os.path.exists(log_file):
        return False

    with open(log_file, "r") as file:
        for line in file:
            if not line.strip():
                continue

            try:
                response = json.loads(line)

                if (
                    response.get("source_ip") == source_ip
                    and response.get("action") == action
                ):
                    return True

            except json.JSONDecodeError:
                continue

    return False


def save_response(response):
    log_file = "logs/response_actions.json"

    os.makedirs("logs", exist_ok=True)

    with open(log_file, "a") as file:
        file.write(json.dumps(response) + "\n")


if __name__ == "__main__":
    sample_threat = {
        "source_ip": "192.168.1.204",
        "risk_level": "CRITICAL",
        "risk_score": 95,
        "threat": "Brute-force attack"
    }

    response = respond_to_threat(sample_threat)

    if response_already_exists(
        response["source_ip"],
        response["action"]
    ):
        print("--- Autonomous Response ---")
        print("Threat already handled.")
        print(f"Source IP: {response['source_ip']}")
        print(f"Action: {response['action']}")

    else:
        save_response(response)

        print("--- Autonomous Response ---")
        print(f"Source IP: {response['source_ip']}")
        print(f"Risk Level: {response['risk_level']}")
        print(f"Action: {response['action']}")