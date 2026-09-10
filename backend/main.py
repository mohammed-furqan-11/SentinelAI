from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from backend.security.security_pipeline import process_security_event
from backend.security.log_reader import read_security_events
from backend.security.event_generator import save_event
from backend.security.incident_manager import create_incident
from backend.security.response_engine import (
    save_response,
    response_already_exists
)
from backend.database import get_database_connection

import json
import os
import asyncio


app = FastAPI(
    title="SentinelAI",
    description="AI-Powered Autonomous Cyber Threat Detection & Response Platform",
    version="1.0.0"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {
        "message": "SentinelAI Cyber Threat Detection Platform is Running!"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "SentinelAI Backend"
    }


@app.get("/api/security/event")
def security_event():
    result = process_security_event()

    return result


@app.get("/api/security/events")
def recent_security_events():
    connection = get_database_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            timestamp,
            event_type,
            source_ip,
            username,
            risk_level,
            risk_score,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            created_at
        FROM security_events
        ORDER BY id DESC
        LIMIT 20
    """)

    rows = cursor.fetchall()

    cursor.close()
    connection.close()

    events = []

    for row in rows:
        events.append({
            "id": row[0],
            "timestamp": row[1].isoformat(),
            "event_type": row[2],
            "source_ip": row[3],
            "username": row[4],
            "risk_level": row[5],
            "risk_score": float(row[6]) if row[6] is not None else None,
            "destination_ip": row[7],
            "protocol": row[8],
            "source_port": row[9],
            "destination_port": row[10],
            "created_at": row[11].isoformat() if row[11] else None
        })

    events.reverse()

    return {
        "total_events": len(events),
        "events": events
    }


@app.get("/api/security/network/events")
def network_security_events():
    connection = get_database_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            timestamp,
            event_type,
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            risk_level,
            risk_score
        FROM security_events
        WHERE event_type IN (
            'network_activity',
            'possible_port_scan',
            'suspicious_network_service'
        )
        ORDER BY id DESC
        LIMIT 50
    """)

    rows = cursor.fetchall()

    cursor.close()
    connection.close()

    events = []

    for row in rows:
        events.append({
            "id": row[0],
            "timestamp": row[1].isoformat() if row[1] else None,
            "event_type": row[2],
            "source_ip": row[3],
            "destination_ip": row[4],
            "protocol": row[5],
            "source_port": row[6],
            "destination_port": row[7],
            "risk_level": row[8],
            "risk_score": float(row[9]) if row[9] is not None else None
        })

    return {
        "total_events": len(events),
        "events": events
    }


@app.get("/api/security/incidents")
def security_incidents():
    log_file = "logs/incidents.json"

    incidents = []

    if os.path.exists(log_file):
        with open(log_file, "r") as file:
            for line in file:
                if line.strip():
                    try:
                        incidents.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

    return {
        "total_incidents": len(incidents),
        "incidents": incidents[-20:]
    }


@app.get("/api/security/responses")
def security_responses():
    log_file = "logs/response_actions.json"

    responses = []

    if os.path.exists(log_file):
        with open(log_file, "r") as file:
            for line in file:
                if line.strip():
                    try:
                        responses.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

    return {
        "total_responses": len(responses),
        "responses": responses[-20:]
    }


@app.get("/api/security/summary")
def security_summary():
    connection = get_database_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM security_events
    """)

    total_events = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM security_events
        WHERE risk_level = 'CRITICAL'
    """)

    critical_events = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM security_events
        WHERE risk_level = 'HIGH'
    """)

    high_events = cursor.fetchone()[0]

    cursor.close()
    connection.close()

    incidents = []
    responses = []

    incident_file = "logs/incidents.json"
    response_file = "logs/response_actions.json"

    if os.path.exists(incident_file):
        with open(incident_file, "r") as file:
            for line in file:
                if line.strip():
                    try:
                        incidents.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

    if os.path.exists(response_file):
        with open(response_file, "r") as file:
            for line in file:
                if line.strip():
                    try:
                        responses.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

    blocked_ips = sum(
        1
        for response in responses
        if response.get("action") == "BLOCK_IP"
    )

    alerts = sum(
        1
        for response in responses
        if response.get("action") == "ALERT_ADMIN"
    )

    return {
        "total_events": total_events,
        "total_incidents": len(incidents),
        "critical_incidents": critical_events,
        "high_incidents": high_events,
        "blocked_ips": blocked_ips,
        "admin_alerts": alerts
    }


@app.websocket("/ws/security")
async def security_websocket(websocket: WebSocket):
    await websocket.accept()

    print("SentinelAI WebSocket client connected.")

    try:
        while True:

            result = process_security_event()

            event = result["event"]

            save_event(event)

            final_risk = result["final_risk"]

            if final_risk["risk_level"] in ["HIGH", "CRITICAL"]:

                if event["event_type"] == "brute_force_attempt":
                    threat_name = "Brute-force attack"
                else:
                    threat_name = "Suspicious login"

                threat = {
                    "source_ip": event["source_ip"],
                    "threat": threat_name,
                    "risk_level": final_risk["risk_level"],
                    "risk_score": final_risk["final_risk_score"]
                }

                create_incident(threat)

            response = result.get("response")

            if response:
                source_ip = response.get("source_ip")
                action = response.get("action")

                if (
                    action != "NO_ACTION"
                    and not response_already_exists(
                        source_ip,
                        action
                    )
                ):
                    save_response(response)

            await websocket.send_json(result)

            await asyncio.sleep(5)

    except WebSocketDisconnect:
        print("SentinelAI WebSocket client disconnected.")

    except Exception as error:
        print(f"WebSocket error: {error}")

        try:
            await websocket.close()
        except Exception:
            pass