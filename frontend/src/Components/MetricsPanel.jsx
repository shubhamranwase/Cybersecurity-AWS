import {
    LineChart, Line, XAxis, YAxis,
    Tooltip, ResponsiveContainer, Legend
} from 'recharts';

export default function MetricsPanel({ metrics }) {
    if (!metrics) return null;

    const combined = metrics.api_calls?.map((item, i) => ({
        time: item.time,
        'API Calls': item.value,
        'Errors': metrics.error_rate?.[i]?.value || 0,
        'Login Attempts': metrics.login_attempts?.[i]?.value || 0,
    })) || [];

    return (
        <ResponsiveContainer width="100%" height={220}>
            <LineChart data={combined}>
                <XAxis
                    dataKey="time"
                    stroke="#555"
                    tick={{ fontFamily: 'Share Tech Mono', fontSize: 11 }}
                />
                <YAxis
                    stroke="#555"
                    tick={{ fontFamily: 'Share Tech Mono', fontSize: 11 }}
                />
                <Tooltip
                    contentStyle={{
                        background: '#141414',
                        border: '1px solid #2a2a2a',
                        color: '#e0e0e0',
                        fontFamily: 'Share Tech Mono',
                        fontSize: '11px',
                        borderRadius: '8px'
                    }}
                />
                <Legend
                    wrapperStyle={{
                        fontFamily: 'Share Tech Mono',
                        fontSize: '11px',
                        color: '#888'
                    }}
                />
                <Line
                    type="monotone"
                    dataKey="API Calls"
                    stroke="#00aaff"
                    strokeWidth={2}
                    dot={false}
                />
                <Line
                    type="monotone"
                    dataKey="Errors"
                    stroke="#ff4444"
                    strokeWidth={2}
                    dot={false}
                />
                <Line
                    type="monotone"
                    dataKey="Login Attempts"
                    stroke="#ffaa33"
                    strokeWidth={2}
                    dot={false}
                />
            </LineChart>
        </ResponsiveContainer>
    );
}