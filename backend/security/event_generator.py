from datetime import datetime
import random
import json
import os


def generate_security_event():
    event_types = [
        "successful_login",
        "failed_login",
        "suspicious_login",
        "brute_force_attempt"
    ]

    event = {
        "timestamp": datetime.now().isoformat(),
        "event_type": random.choice(event_types),
        "source_ip": f"192.168.1.{random.randint(1, 254)}",
        "username": random.choice([
            "admin",
            "user1",
            "guest",
            "unknown"
        ])
    }

    return event


def generate_brute_force_attack(attempts=10):
    events = []

    attack_ip = f"192.168.1.{random.randint(1, 254)}"

    for _ in range(attempts):
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "failed_login",
            "source_ip": attack_ip,
            "username": "admin"
        }

        events.append(event)

    return events


def save_event(event):
    log_file = "logs/security_events.json"

    os.makedirs("logs", exist_ok=True)

    with open(log_file, "a") as file:
        file.write(json.dumps(event) + "\n")


if __name__ == "__main__":
    print("--- Normal Security Events ---")

    for _ in range(5):
        event = generate_security_event()
        save_event(event)
        print(event)

    print("\n--- Simulated Brute-Force Attack ---")

    attack_events = generate_brute_force_attack()

    for event in attack_events:
        save_event(event)
        print(event)