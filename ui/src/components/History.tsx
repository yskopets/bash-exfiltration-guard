import { LIMIT, type HistoryEntry } from '../history'

/** A one-line preview, since the sidebar is narrow and commands are not. */
function preview(command: string) {
  return command.replace(/\s+/g, ' ').trim()
}

export function History({
  entries,
  current,
  onPick,
  onClear,
}: {
  entries: HistoryEntry[]
  current: string
  onPick: (command: string) => void
  onClear: () => void
}) {
  return (
    <>
      <div className="col-head">
        <h2>History</h2>
        {entries.length > 0 && (
          <button className="link" onClick={onClear}>
            clear
          </button>
        )}
      </div>

      {entries.length === 0 ? (
        <p className="muted small">
          Commands you assess appear here, most recent first. The last {LIMIT} are kept.
        </p>
      ) : (
        <ul className="history">
          {entries.map((e) => (
            <li key={e.command}>
              <button
                className={`history-item${e.command === current ? ' is-current' : ''}`}
                onClick={() => onPick(e.command)}
                title={e.command}
              >
                <span className={`tag tag-${e.verdict.toLowerCase()}`}>{e.verdict}</span>
                <span className="history-command">{preview(e.command)}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </>
  )
}
