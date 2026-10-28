import { useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BrainCircuit,
  CheckCircle2,
  Cpu,
  Gauge,
  Network,
  Radio,
  Shield,
  ShieldAlert,
  Sparkles,
  Wifi,
  Zap,
} from "lucide-react";
import "./App.css";

const API_URL = "http://localhost:5000";

const emptyState = {
  device_id: "ESP32-Device01",
  mode: "WAITING",
  avg_interval: 0,
  message_rate: 0,
  payload_size: 0,
  anomaly_probability: 0,
  risk_score: 0,
  decision: "WAITING",
  genai_analysis: "",
  mqtt_connected: false,
  updated_at: null,
  last_seen: null,
};

function decisionClass(decision) {
  const d = String(decision).toUpperCase();

  if (d === "BLOCK") return "danger";
  if (d === "SUSPICIOUS") return "danger";
  if (d === "REVIEW") return "warning";
  if (d === "NORMAL") return "safe";

  return "neutral";
}

function App() {
  const [state, setState] = useState(emptyState);
  const [connected, setConnected] = useState(false);
  const [events, setEvents] = useState([]);

  useEffect(() => {
    const fetchState = async () => {
      try {
        const response = await fetch(`${API_URL}/api/state`);

        if (!response.ok) throw new Error("API unavailable");

        const data = await response.json();

        setState(data);
        setConnected(true);

        setEvents((previous) => {
          const event = {
            time: new Date().toLocaleTimeString(),
            decision: data.decision,
            risk: Number(data.risk_score || 0),
          };

          if (
            previous.length > 0 &&
            previous[0].decision === event.decision
          ) {
            return previous;
          }

          return [event, ...previous].slice(0, 8);
        });
      } catch {
        setConnected(false);
      }
    };

    fetchState();

    const interval = setInterval(fetchState, 1000);


return () => clearInterval(interval);
  }, []);

  const tone = decisionClass(state.decision);
  const probability = Number(state.anomaly_probability || 0) * 100;

  const telemetryAge = state.last_seen
    ? Math.max(
        0,
        Math.floor((Date.now() - new Date(state.last_seen).getTime()) / 1000)
      )
    : null;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <div className="brand-icon">
            <Shield size={22} />
          </div>

          <div>
            <div className="brand-title">IOT SECURITY COMMAND CENTER</div>
            <div className="brand-subtitle">
              AI-powered behavioral threat monitoring
            </div>
          </div>
        </div>

        <div className="system-status">
          <span className={`status-dot ${connected ? "online" : "offline"}`} />
          {connected ? "LIVE PIPELINE" : "API OFFLINE"}
        </div>
      </header>

      <main className="dashboard">
        <section className="hero">
          <div>
            <div className="eyebrow">
              <Radio size={14} />
              REAL-TIME IOT TELEMETRY
            </div>

            <h1>
              Device <span>{state.device_id}</span>
            </h1>

            <p>
              Monitoring communication behavior, anomaly probability and
              AI-assisted security interpretation.
            </p>
          </div>

          <div className={`decision-card ${tone}`}>
            <div className="decision-label">SECURITY DECISION</div>

            <div className="decision-value">
              {state.decision}
            </div>

            <div className="decision-score">
              Risk {Number(state.risk_score || 0).toFixed(1)} / 100
            </div>
          </div>
        </section>

        <section className="metric-grid">
          <Metric
            icon={<Activity />}
            label="MESSAGE RATE"
            value={state.message_rate ? state.message_rate.toFixed(1) : "0.0"}
            unit="msg/min"
          />

          <Metric
            icon={<Gauge />}
            label="AVG INTERVAL"
            value={state.avg_interval ? state.avg_interval.toFixed(3) : "0.000"}
            unit="sec"
          />

          <Metric
            icon={<Network />}
            label="PAYLOAD SIZE"
            value={state.payload_size ? state.payload_size.toFixed(1) : "0.0"}
            unit="bytes"
          />

          <Metric
            icon={<BrainCircuit />}
            label="DNN ANOMALY"
            value={probability.toFixed(1)}
            unit="%"
            highlight
          />
        </section>

        <section className="main-grid">
          <div className="panel behavior-panel">
            <PanelTitle
              icon={<Activity />}
              title="COMMUNICATION BEHAVIOR"
              subtitle="Live behavioral telemetry"
            />

            <div className="behavior-visual">
              <div className="behavior-line">
                <div
                  className={`pulse ${tone}`}
                  style={{
                    animationDuration:
                      state.message_rate > 100 ? "0.35s" : "1.8s",
                  }}
                />
              </div>

              <div className="behavior-label">
                <span>DEVICE ACTIVITY</span>
                <strong>{state.mode || "WAITING"}</strong>
              </div>
            </div>

            <div className="behavior-row">
              <span>MQTT CONNECTION</span>
              <strong className={state.mqtt_connected ? "green" : "offline-text"}>
                {state.mqtt_connected ? "CONNECTED" : "OFFLINE"}
              </strong>
            </div>

            <div className="behavior-row">
              <span>MESSAGE FREQUENCY</span>
              <strong>
                {Number(state.message_rate || 0).toFixed(2)} / min
              </strong>
            </div>

            <div className="behavior-row">
              <span>AVERAGE INTERVAL</span>
              <strong>
                {Number(state.avg_interval || 0).toFixed(3)} sec
              </strong>
            </div>

            <div className="behavior-row">
              <span>PAYLOAD</span>
              <strong>
                {Number(state.payload_size || 0).toFixed(1)} bytes
              </strong>
            </div>
          </div>

          <div className="panel ai-panel">
            <PanelTitle
              icon={<BrainCircuit />}
              title="AI ANALYSIS"
              subtitle="DNN anomaly detection"
            />

            <div className="ai-score">
              <div className="score-ring">
                <div>
                  <strong>{probability.toFixed(1)}%</strong>
                  <span>ANOMALY</span>
                </div>
              </div>

              <div className="ai-copy">
                <div className={`badge ${tone}`}>
                  {state.decision}
                </div>

                <p>
                  The DNN evaluates the observed communication behavior against
                  the learned device baseline.
                </p>
              </div>
            </div>

            <div className="risk-bar">
              <div className="risk-header">
                <span>RISK SCORE</span>
                <strong>
                  {Number(state.risk_score || 0).toFixed(1)}/100
                </strong>
              </div>

              <div className="bar">
                <div
                  className={`bar-fill ${tone}`}
                  style={{
                    width: `${Math.min(Number(state.risk_score || 0), 100)}%`,
                  }}
                />
              </div>
            </div>
          </div>
        </section>

        <section className="panel analyst-panel">
          <PanelTitle
            icon={<Sparkles />}
            title="GENAI SECURITY ANALYST"
            subtitle="Evidence-grounded incident interpretation"
          />

          <div className="analyst-content">
            <div className="analyst-icon">
              <Sparkles size={24} />
            </div>

            <div>
              {state.genai_analysis ? (
                <pre>{state.genai_analysis}</pre>
              ) : (
                <p className="muted">
                  Gemini analysis will appear here when the risk engine
                  identifies a suspicious event.
                </p>
              )}
            </div>
          </div>
        </section>

        <section className="bottom-grid">
          <div className="panel">
            <PanelTitle
              icon={<ShieldAlert />}
              title="EVENT TIMELINE"
              subtitle="Security state transitions"
            />

            <div className="timeline">
              {events.length === 0 ? (
                <div className="empty">
                  Waiting for live telemetry...
                </div>
              ) : (
                events.map((event, index) => (
                  <div className="event" key={`${event.time}-${index}`}>
                    <div className={`event-icon ${decisionClass(event.decision)}`}>
                      {event.decision === "NORMAL" ? (
                        <CheckCircle2 size={16} />
                      ) : (
                        <AlertTriangle size={16} />
                      )}
                    </div>

                    <div className="event-info">
                      <strong>{event.decision}</strong>
                      <span>{event.time}</span>
                    </div>

                    <div className="event-risk">
                      {event.risk.toFixed(1)}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="panel architecture">
            <PanelTitle
              icon={<Cpu />}
              title="LIVE PIPELINE"
              subtitle="Detection architecture"
            />

            <div className="pipeline">
              <Node icon={<Wifi />} label="ESP32" />
              <Arrow />
              <Node icon={<Radio />} label="MQTT" />
              <Arrow />
              <Node icon={<BrainCircuit />} label="DNN" />
              <Arrow />
              <Node icon={<Shield />} label="RISK" />
              <Arrow />
              <Node icon={<Sparkles />} label="GENAI" />
            </div>

            <div className="pipeline-note">
              <Zap size={15} />
              <span>
                Controlled suspicious traffic is detected from communication
                behavior rather than claimed as a real-world attack.
              </span>
            </div>
          </div>
        </section>
      </main>

      <footer>
        IOT SECURITY PLATFORM <span>•</span> ESP32 + MQTT + PyTorch + Gemini
      </footer>
    </div>
  );
}

function Metric({ icon, label, value, unit, highlight }) {
  return (
    <div className={`metric ${highlight ? "highlight" : ""}`}>
      <div className="metric-icon">{icon}</div>
      <div className="metric-label">{label}</div>
      <div className="metric-value">
        {value}
        <small>{unit}</small>
      </div>
    </div>
  );
}

function PanelTitle({ icon, title, subtitle }) {
  return (
    <div className="panel-title">
      <div className="panel-title-icon">{icon}</div>
      <div>
        <h2>{title}</h2>
        <p>{subtitle}</p>
      </div>
    </div>
  );
}

function Node({ icon, label }) {
  return (
    <div className="pipeline-node">
      {icon}
      <span>{label}</span>
    </div>
  );
}

function Arrow() {
  return <div className="pipeline-arrow">→</div>;
}

export default App;
