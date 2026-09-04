import os

import psycopg2
from dotenv import load_dotenv


load_dotenv()


DB_CONFIG = {
    "host": os.getenv("POSTGRES_HOST", "localhost"),
    "database": os.getenv("POSTGRES_DATABASE", "sentinelai"),
    "user": os.getenv("POSTGRES_USER", "postgres"),
    "password": os.getenv("POSTGRES_PASSWORD"),
    "port": int(os.getenv("POSTGRES_PORT", "5432"))
}


def get_database_connection():
    return psycopg2.connect(**DB_CONFIG)


def save_security_event(event):
    connection = get_database_connection()
    cursor = connection.cursor()

    query = """
        INSERT INTO security_events (
            timestamp,
            event_type,
            source_ip,
            username,
            risk_level,
            risk_score,
            destination_ip,
            protocol,
            source_port,
            destination_port
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    cursor.execute(
        query,
        (
            event["timestamp"],
            event["event_type"],
            event["source_ip"],
            event.get("username"),
            event.get("risk_level"),
            event.get("risk_score"),
            event.get("destination_ip"),
            event.get("protocol"),
            event.get("source_port"),
            event.get("destination_port")
        )
    )

    connection.commit()

    cursor.close()
    connection.close()