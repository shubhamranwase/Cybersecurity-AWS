import { useState, useEffect } from 'react';
import axios from 'axios';
import AlertCard from './Components/AlertCard';
import LogTable from './Components/LogTable';
import ThreatChart from './Components/ThreatChart';

const API = import.meta.env.VITE_API_URL || 'http://localhost:5000/api'

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
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setUpdated] = useState('');

  const fetchData = async () => {
    try {
      const [gd, ct] = await Promise.all([
        axios.get(`${API}/guardduty`),
        axios.get(`${API}/cloudtrail`),
      ]);
      setFindings(gd.data.findings || []);
      setLogs(ct.data.events || []);
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

  return (
    <div className="dashboard">

      {/* Header */}
      <div className="dashboard__header">
        <div>
          <h1 className="dashboard__title flex-container">
            <h1 className="dashboard__title icon">⚡</h1>
            <h1 className='dashboard__title animated1'>AWS Security Monitor</h1>
          </h1>
          <p className="dashboard__subtitle">Last updated: {lastUpdated || '—'}</p>
        </div>
        <button className="btn-refresh" onClick={fetchData}>
          ↻ Refresh
        </button>
      </div>

      {loading ? (
        <p className="dashboard__loading">⟳ Loading security data...</p>
      ) : (
        <>
          {/* Stat Boxes */}
          <div className="stats-grid">
            <StatBox className="stat-box" label="Total Findings" value={findings.length} color="var(--accent-blue)" />
            <StatBox className="stat-box" label="High Severity" value={highCount} color="var(--accent-red)" />
            <StatBox className="stat-box" label="Medium" value={medCount} color="var(--accent-orange)" />
            <StatBox className="stat-box" label="Low" value={lowCount} color="var(--accent-green)" />
          </div>

          {/* Chart + Alerts */}
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

          {/* Log Table */}
          <div className="card card--full">
            <h2 className="card__title">CloudTrail — Recent Login Events</h2>
            <LogTable logs={logs} />
          </div>
        </>
      )}

    </div>
  );
}