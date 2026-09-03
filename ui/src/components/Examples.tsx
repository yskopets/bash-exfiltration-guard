import { examples } from '../examples'

export function Examples({
  current,
  onPick,
}: {
  current: string
  onPick: (command: string) => void
}) {
  return (
    <>
      <div className="col-head">
        <h2>Examples</h2>
      </div>
      <p className="muted small">
        Each reaches a different verdict for a different reason. Between them they
        exercise every rule.
      </p>
      <ul className="examples">
        {examples.map((ex) => (
          <li key={ex.title}>
            <button
              className={`example${ex.command === current ? ' is-current' : ''}`}
              onClick={() => onPick(ex.command)}
              title={ex.command}
            >
              <span className="example-title">{ex.title}</span>
              <span className="example-note">{ex.note}</span>
            </button>
          </li>
        ))}
      </ul>
    </>
  )
}
