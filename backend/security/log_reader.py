import json


def read_security_events(log_file="logs/security_events.json"):
    events = []

    try:
        with open(log_file, "r") as file:
            for line in file:
                line = line.strip()

                if line:
                    events.append(json.loads(line))

    except FileNotFoundError:
        print(f"Log file not found: {log_file}")

    except json.JSONDecodeError as error:
        print(f"Invalid JSON data: {error}")

    return events


if __name__ == "__main__":
    events = read_security_events()

    print(f"Total events loaded: {len(events)}")

    for event in events:
        print(event)