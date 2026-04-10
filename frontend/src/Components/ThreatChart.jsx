import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

const COLORS = {
  HIGH: '#ff4444', MEDIUM: '#ffaa33',
  LOW: '#00ff88', CRITICAL: '#ff44ff'
};

export default function ThreatChart({ findings }) {
  const counts = findings.reduce((acc, f) => {
    const sev = f.severity >= 7 ? 'HIGH' : f.severity >= 4 ? 'MEDIUM' : 'LOW';
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {});

  const data = Object.entries(counts).map(([name, value]) => ({ name, value }));

  return (
    <ResponsiveContainer width="100%" height={200}>
      <BarChart data={data}>
        <XAxis dataKey="name" stroke="#555" tick={{ fontFamily: 'Share Tech Mono', fontSize: 14 }} />
        <YAxis stroke="#555" tick={{ fontFamily: 'Share Tech Mono', fontSize: 14 }} />
        <Tooltip
          contentStyle={{
            background: '#ffffff',
            border: '1px solid #2a2a2a',
            color: '#6d6d6d',
            fontFamily: 'Share Tech Mono',
            fontSize: '16px',
            borderRadius: '8px'
          }}
        />
        <Bar dataKey="value" radius={[4, 4, 0, 0]}>
          {data.map((entry) => (
            <Cell key={entry.name} fill={COLORS[entry.name] || '#888'} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}