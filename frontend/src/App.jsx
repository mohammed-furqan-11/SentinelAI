import { useEffect, useState } from "react";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid
} from "recharts";

import "./App.css";

function App() {
  const [summary, setSummary] = useState({
    total_events: 0,
    total_incidents: 0,
    critical_incidents: 0,
    high_incidents: 0,
    blocked_ips: 0,
    admin_alerts: 0
  });

  const [events, setEvents] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [responses, setResponses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [liveConnected, setLiveConnected] = useState(false);
  const [lastLiveEvent, setLastLiveEvent] = useState(null);

  const loadSecurityData = async () => {
    try {
      const [
        summaryResponse,
        eventsResponse,
        incidentsResponse,
        responsesResponse
      ] = await Promise.all([
        fetch("http://127.0.0.1:8000/api/security/summary"),
        fetch("http://127.0.0.1:8000/api/security/events"),
        fetch("http://127.0.0.1:8000/api/security/incidents"),
        fetch("http://127.0.0.1:8000/api/security/responses")
      ]);

      const summaryData = await summaryResponse.json();
      const eventsData = await eventsResponse.json();
      const incidentsData = await incidentsResponse.json();
      const responsesData = await responsesResponse.json();

      setSummary(summaryData);
      setEvents(eventsData.events || []);
      setIncidents(incidentsData.incidents || []);
      setResponses(responsesData.responses || []);
      setLoading(false);
    } catch (error) {
      console.error("SentinelAI connection error:", error);
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSecurityData();

    let socket;
    let reconnectTimer;
    let stopped = false;

    const connectWebSocket = () => {
      if (stopped) {
        return;
      }

      socket = new WebSocket("ws://127.0.0.1:8000/ws/security");

      socket.onopen = () => {
        console.log("SentinelAI live monitoring connected.");
        setLiveConnected(true);
      };

      socket.onmessage = async (message) => {
        try {
          const result = JSON.parse(message.data);

          setLastLiveEvent(result);

          if (result.event) {
            setEvents((currentEvents) => {
              const updatedEvents = [
                ...currentEvents,
                result.event
              ];

              return updatedEvents.slice(-20);
            });
          }

          await loadSecurityData();

        } catch (error) {
          console.error(
            "Invalid SentinelAI WebSocket message:",
            error
          );
        }
      };

      socket.onerror = (error) => {
        console.error(
          "SentinelAI WebSocket error:",
          error
        );
      };

      socket.onclose = () => {
        setLiveConnected(false);

        if (!stopped) {
          reconnectTimer = setTimeout(() => {
            connectWebSocket();
          }, 3000);
        }
      };
    };

    connectWebSocket();

    return () => {
      stopped = true;

      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
      }

      if (socket) {
        socket.close();
      }
    };
  }, []);

  const getRiskClass = (level) => {
    if (level === "CRITICAL") return "critical-text";
    if (level === "HIGH") return "high-text";
    if (level === "MEDIUM") return "medium-text";
    return "low-text";
  };

  const getEventLabel = (eventType) => {
    if (eventType === "brute_force_attempt") {
      return "Brute-Force Attack";
    }

    if (eventType === "suspicious_login") {
      return "Suspicious Login";
    }

    if (eventType === "failed_login") {
      return "Failed Login";
    }

    if (eventType === "successful_login") {
      return "Successful Login";
    }

    return eventType;
  };

  const getResponseClass = (action) => {
    if (action === "BLOCK_IP") {
      return "critical-action";
    }

    if (action === "ALERT_ADMIN") {
      return "alert-action";
    }

    return "normal-action";
  };

  const criticalCount = incidents.filter(
    (incident) => incident.risk_level === "CRITICAL"
  ).length;

  const highCount = incidents.filter(
    (incident) => incident.risk_level === "HIGH"
  ).length;

  const mediumCount = incidents.filter(
    (incident) => incident.risk_level === "MEDIUM"
  ).length;

  const lowCount = incidents.filter(
    (incident) => incident.risk_level === "LOW"
  ).length;

  const threatDistribution = [
    {
      name: "Critical",
      value: criticalCount,
      color: "#ef4444"
    },
    {
      name: "High",
      value: highCount,
      color: "#f97316"
    },
    {
      name: "Medium",
      value: mediumCount,
      color: "#eab308"
    },
    {
      name: "Low",
      value: lowCount,
      color: "#22c55e"
    }
  ].filter((item) => item.value > 0);

  const eventStatistics = [
    {
      name: "Successful",
      count: events.filter(
        (event) =>
          event.event_type === "successful_login"
      ).length
    },
    {
      name: "Failed",
      count: events.filter(
        (event) =>
          event.event_type === "failed_login"
      ).length
    },
    {
      name: "Suspicious",
      count: events.filter(
        (event) =>
          event.event_type === "suspicious_login"
      ).length
    },
    {
      name: "Brute Force",
      count: events.filter(
        (event) =>
          event.event_type === "brute_force_attempt"
      ).length
    }
  ];

  const responseStatistics = [
    {
      name: "Blocked IPs",
      count: summary.blocked_ips
    },
    {
      name: "Admin Alerts",
      count: summary.admin_alerts
    }
  ];

  return (
    <div className="dashboard">

      <header className="topbar">

        <div>
          <h1>SentinelAI</h1>

          <p>
            AI-Powered Autonomous Cyber Threat Detection & Response
          </p>
        </div>

        <div className="system-status">

          <span
            className="status-dot"
            style={{
              background: liveConnected
                ? "#22c55e"
                : "#ef4444",
              boxShadow: liveConnected
                ? "0 0 12px #22c55e"
                : "0 0 12px #ef4444"
            }}
          ></span>

          {liveConnected
            ? "Live System Online"
            : "Reconnecting..."}

        </div>

      </header>

      <main className="main-content">

        <section className="welcome">

          <div>

            <h2>
              Security Operations Center
            </h2>

            <p>
              Real-time monitoring of threats, incidents, AI predictions
              and autonomous responses.
            </p>

          </div>

          <div
            className="live-badge"
            style={{
              borderColor: liveConnected
                ? "#14532d"
                : "#7f1d1d",
              background: liveConnected
                ? "#052e16"
                : "#450a0a",
              color: liveConnected
                ? "#86efac"
                : "#f87171"
            }}
          >
            {liveConnected
              ? "● LIVE MONITORING"
              : "● RECONNECTING"}
          </div>

        </section>

        {lastLiveEvent && (
          <section className="live-event-banner">

            <div>

              <strong>
                LIVE THREAT ENGINE
              </strong>

              <span>
                New event received from SentinelAI
              </span>

            </div>

            <div className="live-event-details">

              <span>
                {getEventLabel(
                  lastLiveEvent.event?.event_type
                )}
              </span>

              <span>
                {lastLiveEvent.event?.source_ip}
              </span>

              <span
                className={getRiskClass(
                  lastLiveEvent.final_risk?.risk_level
                )}
              >
                {lastLiveEvent.final_risk?.risk_level}
              </span>

            </div>

          </section>
        )}

        <section className="stats-grid">

          <div className="stat-card">

            <div className="stat-title">
              Total Events
            </div>

            <div className="stat-value">
              {loading
                ? "..."
                : summary.total_events}
            </div>

            <div className="stat-description">
              Security events analyzed
            </div>

          </div>

          <div className="stat-card critical">

            <div className="stat-title">
              Critical Threats
            </div>

            <div className="stat-value">
              {loading
                ? "..."
                : summary.critical_incidents}
            </div>

            <div className="stat-description">
              Critical incidents detected
            </div>

          </div>

          <div className="stat-card high">

            <div className="stat-title">
              High Threats
            </div>

            <div className="stat-value">
              {loading
                ? "..."
                : summary.high_incidents}
            </div>

            <div className="stat-description">
              High-risk incidents
            </div>

          </div>

          <div className="stat-card blocked">

            <div className="stat-title">
              Blocked IPs
            </div>

            <div className="stat-value">
              {loading
                ? "..."
                : summary.blocked_ips}
            </div>

            <div className="stat-description">
              Autonomous responses
            </div>

          </div>

        </section>

        <section className="content-grid">

          <div className="panel">

            <div className="panel-header">

              <h3>
                Recent Security Events
              </h3>

              <span className="panel-label">
                LIVE DATA
              </span>

            </div>

            <div className="event-list">

              {events.length === 0 ? (

                <div className="empty-state">
                  No security events available.
                </div>

              ) : (

                events
                  .slice(-6)
                  .reverse()
                  .map((event, index) => (

                    <div
                      className="event-row"
                      key={`${event.timestamp}-${index}`}
                    >

                      <div className="event-indicator">

                        {event.event_type ===
                        "brute_force_attempt"
                          ? "!"
                          : event.event_type ===
                            "suspicious_login"
                          ? "!"
                          : "•"}

                      </div>

                      <div className="event-info">

                        <strong>
                          {getEventLabel(
                            event.event_type
                          )}
                        </strong>

                        <span>
                          {event.source_ip} ·{" "}
                          {event.username}
                        </span>

                      </div>

                      <div className="event-time">
                        {new Date(
                          event.timestamp
                        ).toLocaleTimeString()}
                      </div>

                    </div>

                  ))

              )}

            </div>

          </div>

          <div className="panel">

            <div className="panel-header">

              <h3>
                Autonomous Responses
              </h3>

              <span className="panel-label">
                RESPONSE ENGINE
              </span>

            </div>

            <div className="response-list">

              {responses.length === 0 ? (

                <div className="empty-state">
                  No responses available.
                </div>

              ) : (

                responses
                  .slice(-6)
                  .reverse()
                  .map((response, index) => (

                    <div
                      className="response-item"
                      key={`${response.timestamp}-${index}`}
                    >

                      <div>

                        <strong>
                          {response.action}
                        </strong>

                        <span>
                          {response.source_ip}
                        </span>

                      </div>

                      <span
                        className={`action ${getResponseClass(
                          response.action
                        )}`}
                      >

                        {response.action ===
                        "BLOCK_IP"
                          ? "BLOCKED"
                          : response.action ===
                            "ALERT_ADMIN"
                          ? "ALERTED"
                          : "SAFE"}

                      </span>

                    </div>

                  ))

              )}

            </div>

          </div>

        </section>

        <section className="analytics-section">

          <div className="analytics-header">

            <div>

              <h2>
                Security Analytics
              </h2>

              <p>
                Threat distribution, event activity and autonomous
                response statistics.
              </p>

            </div>

            <div className="analytics-status">
              {liveConnected
                ? "AI ANALYTICS · LIVE"
                : "AI ANALYTICS"}
            </div>

          </div>

          <div className="analytics-grid">

            <div className="analytics-card">

              <div className="analytics-card-header">

                <h3>
                  Threat Distribution
                </h3>

                <span>
                  INCIDENT RISK
                </span>

              </div>

              <div className="chart-container">

                {threatDistribution.length === 0 ? (

                  <div className="empty-state">
                    No threat data available.
                  </div>

                ) : (

                  <ResponsiveContainer
                    width="100%"
                    height={280}
                  >

                    <PieChart>

                      <Pie
                        data={threatDistribution}
                        cx="50%"
                        cy="50%"
                        outerRadius={95}
                        innerRadius={55}
                        paddingAngle={3}
                        dataKey="value"
                        nameKey="name"
                      >

                        {threatDistribution.map(
                          (entry, index) => (

                            <Cell
                              key={`cell-${index}`}
                              fill={entry.color}
                            />

                          )
                        )}

                      </Pie>

                      <Tooltip />

                    </PieChart>

                  </ResponsiveContainer>

                )}

              </div>

              <div className="chart-legend">

                {threatDistribution.map(
                  (item, index) => (

                    <div
                      className="legend-item"
                      key={index}
                    >

                      <span
                        className="legend-dot"
                        style={{
                          background: item.color,
                          boxShadow:
                            `0 0 7px ${item.color}`
                        }}
                      ></span>

                      <span>
                        {item.name}
                      </span>

                      <strong>
                        {item.value}
                      </strong>

                    </div>

                  )
                )}

              </div>

            </div>

            <div className="analytics-card">

              <div className="analytics-card-header">

                <h3>
                  Event Activity
                </h3>

                <span>
                  EVENT TYPES
                </span>

              </div>

              <div className="chart-container">

                <ResponsiveContainer
                  width="100%"
                  height={280}
                >

                  <BarChart
                    data={eventStatistics}
                    margin={{
                      top: 10,
                      right: 10,
                      left: -15,
                      bottom: 5
                    }}
                  >

                    <CartesianGrid
                      strokeDasharray="3 3"
                      stroke="#1f2937"
                    />

                    <XAxis
                      dataKey="name"
                      tick={{
                        fill: "#94a3b8",
                        fontSize: 10
                      }}
                      axisLine={{
                        stroke: "#334155"
                      }}
                      tickLine={false}
                    />

                    <YAxis
                      allowDecimals={false}
                      tick={{
                        fill: "#94a3b8",
                        fontSize: 10
                      }}
                      axisLine={false}
                      tickLine={false}
                    />

                    <Tooltip />

                    <Bar
                      dataKey="count"
                      fill="#8b5cf6"
                      radius={[5, 5, 0, 0]}
                    />

                  </BarChart>

                </ResponsiveContainer>

              </div>

              <div className="analytics-mini-stats">

                <div>

                  <strong>
                    {summary.total_events}
                  </strong>

                  <span>
                    Total Events
                  </span>

                </div>

                <div>

                  <strong>
                    {summary.total_incidents}
                  </strong>

                  <span>
                    Incidents
                  </span>

                </div>

                <div>

                  <strong>
                    {summary.admin_alerts}
                  </strong>

                  <span>
                    Alerts
                  </span>

                </div>

              </div>

            </div>

            <div className="analytics-card response-analytics">

              <div className="analytics-card-header">

                <h3>
                  Autonomous Response Activity
                </h3>

                <span>
                  RESPONSE ENGINE
                </span>

              </div>

              <div className="response-stat-grid">

                <div className="response-stat critical-stat">

                  <div className="response-stat-value">
                    {summary.blocked_ips}
                  </div>

                  <div className="response-stat-label">
                    IPs Blocked
                  </div>

                  <div className="response-stat-description">
                    Critical threats automatically contained
                  </div>

                </div>

                <div className="response-stat alert-stat">

                  <div className="response-stat-value">
                    {summary.admin_alerts}
                  </div>

                  <div className="response-stat-label">
                    Admin Alerts
                  </div>

                  <div className="response-stat-description">
                    High-risk threats escalated
                  </div>

                </div>

              </div>

              <div className="response-bar-container">

                <ResponsiveContainer
                  width="100%"
                  height={180}
                >

                  <BarChart
                    data={responseStatistics}
                    layout="vertical"
                    margin={{
                      top: 5,
                      right: 20,
                      left: 20,
                      bottom: 5
                    }}
                  >

                    <CartesianGrid
                      strokeDasharray="3 3"
                      stroke="#1f2937"
                    />

                    <XAxis
                      type="number"
                      allowDecimals={false}
                      tick={{
                        fill: "#94a3b8",
                        fontSize: 10
                      }}
                      axisLine={{
                        stroke: "#334155"
                      }}
                      tickLine={false}
                    />

                    <YAxis
                      type="category"
                      dataKey="name"
                      width={85}
                      tick={{
                        fill: "#94a3b8",
                        fontSize: 10
                      }}
                      axisLine={false}
                      tickLine={false}
                    />

                    <Tooltip />

                    <Bar
                      dataKey="count"
                      fill="#06b6d4"
                      radius={[0, 5, 5, 0]}
                    />

                  </BarChart>

                </ResponsiveContainer>

              </div>

            </div>

          </div>

        </section>

        <section className="panel">

          <div className="panel-header">

            <h3>
              Security Incidents
            </h3>

            <span className="panel-label">
              {summary.total_incidents} TOTAL
            </span>

          </div>

          <div className="incident-table">

            <div className="incident-header">

              <span>
                INCIDENT
              </span>

              <span>
                THREAT
              </span>

              <span>
                SOURCE IP
              </span>

              <span>
                RISK
              </span>

              <span>
                STATUS
              </span>

            </div>

            {incidents.length === 0 ? (

              <div className="empty-state">
                No incidents available.
              </div>

            ) : (

              incidents
                .slice(-10)
                .reverse()
                .map((incident, index) => (

                  <div
                    className="incident-row"
                    key={`${incident.incident_id}-${index}`}
                  >

                    <span className="incident-id">
                      {incident.incident_id}
                    </span>

                    <span>
                      {incident.threat}
                    </span>

                    <span>
                      {incident.source_ip}
                    </span>

                    <span
                      className={getRiskClass(
                        incident.risk_level
                      )}
                    >

                      {incident.risk_level}

                      <small>
                        {incident.risk_score}
                      </small>

                    </span>

                    <span className="status-open">
                      {incident.status}
                    </span>

                  </div>

                ))

            )}

          </div>

        </section>

        <section className="panel incidents-panel">

          <div className="panel-header">

            <h3>
              Security Pipeline
            </h3>

            <span className="panel-label">
              AI PROCESSING
            </span>

          </div>

          <div className="pipeline">

            <div className="pipeline-step">

              <div className="pipeline-number">
                01
              </div>

              <strong>
                Event Collection
              </strong>

              <span>
                Security Events
              </span>

            </div>

            <div className="pipeline-arrow">
              →
            </div>

            <div className="pipeline-step">

              <div className="pipeline-number">
                02
              </div>

              <strong>
                Rule Detection
              </strong>

              <span>
                Threat Analysis
              </span>

            </div>

            <div className="pipeline-arrow">
              →
            </div>

            <div className="pipeline-step">

              <div className="pipeline-number">
                03
              </div>

              <strong>
                ML Detection
              </strong>

              <span>
                AI Prediction
              </span>

            </div>

            <div className="pipeline-arrow">
              →
            </div>

            <div className="pipeline-step">

              <div className="pipeline-number">
                04
              </div>

              <strong>
                Risk Engine
              </strong>

              <span>
                Final Risk Score
              </span>

            </div>

            <div className="pipeline-arrow">
              →
            </div>

            <div className="pipeline-step">

              <div className="pipeline-number">
                05
              </div>

              <strong>
                Autonomous Response
              </strong>

              <span>
                Action Taken
              </span>

            </div>

          </div>

        </section>

      </main>

      <footer>
        SentinelAI © 2026 · Autonomous Cyber Threat Detection Platform
      </footer>

    </div>
  );
}

export default App;