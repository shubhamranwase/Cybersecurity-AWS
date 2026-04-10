export default function LogTable({ logs }) {

  if (!logs || logs.length === 0) {
    return <p className="card__empty">No logs available.</p>
  }

  return (
    <div className="log-table-wrap">
      <table className="log-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>User</th>
            <th>Event</th>
            <th>Source IP</th>
          </tr>
        </thead>
        <tbody>
          {logs.map((log, i) => (
            <tr key={i}>
              <td className="log-table__time">
                {new Date(log.event_time).toLocaleTimeString()}
              </td>
              <td className="log-table__user">{log.username}</td>
              <td className="log-table__event">{log.event_name}</td>
              <td className="log-table__ip">{log.source_ip}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}