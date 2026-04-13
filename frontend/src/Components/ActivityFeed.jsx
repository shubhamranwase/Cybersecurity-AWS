export default function ActivityFeed({ alarms, history }) {
    const allItems = [
        ...(alarms || []).map(a => ({
            ...a,
            itemType: 'alarm',
            time: a.updated_at
        })),
        ...(history || []).map(h => ({
            ...h,
            itemType: 'history',
            time: h.timestamp
        }))
    ].sort((a, b) => new Date(b.time) - new Date(a.time));

    if (!allItems.length) {
        return <p className="card__empty">No activity recorded.</p>;
    }

    return (
        <div className="activity-feed">
            {allItems.map((item, i) => (
                <div key={i} className="activity-item">
                    <div className="activity-item__icon">
                        {item.itemType === 'alarm'
                            ? item.state === 'ALARM' ? '🔴' : '🟢'
                            : '✅'}
                    </div>
                    <div className="activity-item__content">
                        <div className="activity-item__title">
                            {item.name || item.title}
                        </div>
                        <div className="activity-item__meta">
                            {item.description || item.type}
                            <span className="activity-item__time">
                                {new Date(item.time).toLocaleString()}
                            </span>
                        </div>
                    </div>
                    <div className={`activity-item__badge
            activity-item__badge--${item.state || item.status}`}>
                        {item.state || item.status}
                    </div>
                </div>
            ))}
        </div>
    );
}