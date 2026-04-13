import { useState, useEffect } from 'react';
import axios from 'axios';
import AlertCard from './Components/AlertCard';
import LogTable from './Components/LogTable';
import ThreatChart from './Components/ThreatChart';
import MetricsPanel from './Components/MetricsPanel';
import ActivityFeed from './Components/ActivityFeed';

const API = '/api';

function StatBox({ label, value, color }) {
  return (
    <div className="stat-box" style={{ '--stat-color': color }}>
      <div className="stat-box__value">{value}</div>
      <div className="stat-box__label">{label}</div>
    </div>
  );
}

export default function Dashboard() {
  const [findings, setFindings] = useState([]);
  const [logs, setLogs] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [alarms, setAlarms] = useState([]);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setUpdated] = useState('');

  const fetchData = async () => {
    try {
      const [gd, ct, mt, al, hi] = await Promise.all([
        axios.get(`${API}/guardduty`),
        axios.get(`${API}/cloudtrail`),
        axios.get(`${API}/metrics`),
        axios.get(`${API}/alarms`),
        axios.get(`${API}/history`),
      ]);
      setFindings(gd.data.findings || []);
      setLogs(ct.data.events || []);
      setMetrics(mt.data || null);
      setAlarms(al.data.alarms || []);
      setHistory(hi.data.history || []);
      setUpdated(new Date().toLocaleTimeString());
    } catch (e) {
      console.error('API error:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  const highCount = findings.filter(f => f.severity >= 7).length;
  const medCount = findings.filter(f => f.severity >= 4 && f.severity < 7).length;
  const lowCount = findings.filter(f => f.severity < 4).length;
  const alarmCount = alarms.filter(a => a.state === 'ALARM').length;

  return (
    <div className="dashboard">

      {/* Header */}
      <div className="dashboard__header">
        <div>
          <h1 className="dashboard__title">⚡ AWS Security Monitor</h1>
          <p className="dashboard__subtitle">Last updated: {lastUpdated || '—'}</p>
        </div>
        <button className="btn-refresh" onClick={fetchData}>↻ Refresh</button>
      </div>

      {loading ? (
        <p className="dashboard__loading">⟳ Loading security data...</p>
      ) : (
        <>
          {/* Stat Boxes */}
          <div className="stats-grid">
            <StatBox label="Total Threats" value={findings.length} color="var(--accent-blue)" />
            <StatBox label="High Severity" value={highCount} color="var(--accent-red)" />
            <StatBox label="Medium" value={medCount} color="var(--accent-orange)" />
            <StatBox label="Low" value={lowCount} color="var(--accent-green)" />
            <StatBox label="Active Alarms" value={alarmCount} color="var(--accent-purple)" />
          </div>

          {/* Row 1 — Chart + Alerts */}
          <div className="main-grid">
            <div className="card">
              <h2 className="card__title">Severity Breakdown</h2>
              <ThreatChart findings={findings} />
            </div>
            <div className="card card--scrollable">
              <h2 className="card__title">Active Threats ({findings.length})</h2>
              {findings.length
                ? findings.map(f => <AlertCard key={f.id} {...f} />)
                : <p className="card__empty">✅ No active threats detected</p>
              }
            </div>
          </div>

          {/* Row 2 — Metrics Line Chart */}
          <div className="card card--full">
            <h2 className="card__title">📈 CloudWatch Metrics — Last 24 Hours</h2>
            <MetricsPanel metrics={metrics} />
          </div>

          {/* Row 3 — Activity Feed + Log Table */}
          <div className="main-grid" style={{ marginTop: '22px' }}>
            <div className="card card--scrollable">
              <h2 className="card__title">🔔 Activity Feed</h2>
              <ActivityFeed alarms={alarms} history={history} />
            </div>
            <div className="card card--scrollable">
              <h2 className="card__title">CloudTrail — Login Events</h2>
              <LogTable logs={logs} />
            </div>
          </div>

        </>
      )}
    </div>
  );
}