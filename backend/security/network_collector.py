from datetime import datetime
from collections import defaultdict

from scapy.all import sniff, IP, TCP, UDP

from backend.security.security_pipeline import process_security_event


# Common TCP/UDP ports that can be useful for security monitoring.
SUSPICIOUS_PORTS = {
    21: "FTP",
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
    5900: "VNC"
}


connection_tracker = defaultdict(set)


def classify_network_activity(packet):
    if not packet.haslayer(IP):
        return None

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    protocol = "OTHER"
    source_port = None
    destination_port = None

    if packet.haslayer(TCP):
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif packet.haslayer(UDP):
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    threat_type = "network_activity"
    risk_level = "LOW"
    risk_score = 0

    # Track unique destination ports for each source IP.
    if destination_port is not None:
        connection_tracker[source_ip].add(destination_port)

    unique_ports = len(connection_tracker[source_ip])

    # Detect potential port scanning behavior.
    if unique_ports >= 10:
        threat_type = "possible_port_scan"
        risk_level = "HIGH"
        risk_score = 75

    # Detect traffic directed toward commonly abused services.
    elif destination_port in SUSPICIOUS_PORTS:
        threat_type = "suspicious_network_service"
        risk_level = "MEDIUM"
        risk_score = 50

    event = {
        "timestamp": datetime.now().isoformat(),
        "event_type": threat_type,
        "source_ip": source_ip,
        "username": None,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": destination_port,
        "risk_level": risk_level,
        "risk_score": risk_score
    }

    return event


def process_network_packet(packet):
    event = classify_network_activity(packet)

    if event is None:
        return None

    result = process_security_event(event)

    return result


def start_network_monitor(packet_count=10):
    print("SentinelAI Real Network Threat Monitor")
    print("--------------------------------------")
    print(f"Capturing {packet_count} packets...\n")

    processed_events = []

    def packet_handler(packet):
        try:
            result = process_network_packet(packet)

            if result is None:
                return

            processed_events.append(result)

            event = result["event"]
            final_risk = result["final_risk"]

            print(
                f"[NETWORK] "
                f"{event['source_ip']} -> "
                f"{event['destination_ip']} | "
                f"{event['protocol']} | "
                f"{event['event_type']} | "
                f"Risk: {final_risk['risk_level']} "
                f"({final_risk['final_risk_score']})"
            )

        except Exception as error:
            print(
                f"[NETWORK ERROR] {error}"
            )

    sniff(
        prn=packet_handler,
        count=packet_count,
        store=False
    )

    print(
        f"\nProcessed network events: "
        f"{len(processed_events)}"
    )

    return processed_events


if __name__ == "__main__":
    start_network_monitor(10)