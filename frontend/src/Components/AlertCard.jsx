function getSeverityLabel(severity) {
  if (typeof severity === 'string') return severity.toUpperCase();
  if (severity >= 9) return 'CRITICAL';
  if (severity >= 7) return 'HIGH';
  if (severity >= 4) return 'MEDIUM';
  return 'LOW';
}

export default function AlertCard({ title, severity, type, region, status }) {
  const label = getSeverityLabel(severity);

  return (
    <div className={`alert-card alert-card--${label}`}>
      <div className="alert-card__top">
        <span className="alert-card__title">{title}</span>
        <span className={`alert-card__severity alert-card__severity--${label}`}>
          {label}
        </span>
      </div>
      <div className="alert-card__meta">
        <span>🌐 {region}</span>
        <span>⚠️ {type}</span>
        <span className={`alert-card__status--${status}`}>● {status}</span>
      </div>
    </div>
  );
}