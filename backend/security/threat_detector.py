def detect_threat(event):
    event_type = event.get("event_type")

    risk_levels = {
        "successful_login": {
            "risk_level": "LOW",
            "score": 10
        },
        "failed_login": {
            "risk_level": "MEDIUM",
            "score": 40
        },
        "suspicious_login": {
            "risk_level": "HIGH",
            "score": 70
        },
        "brute_force_attempt": {
            "risk_level": "CRITICAL",
            "score": 95
        }
    }

    result = risk_levels.get(
        event_type,
        {
            "risk_level": "UNKNOWN",
            "score": 0
        }
    )

    return {
        "event": event,
        "risk_level": result["risk_level"],
        "risk_score": result["score"]
    }


if __name__ == "__main__":
    sample_event = {
        "event_type": "brute_force_attempt",
        "source_ip": "192.168.1.100",
        "username": "admin"
    }

    result = detect_threat(sample_event)
    print(result)