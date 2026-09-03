import type { Assessment, FlowView } from '../api'

const outcomeLabel: Record<string, string> = {
  exposed: 'EXPOSED',
  'intended-use': 'INTENDED USE',
  unresolved: 'UNKNOWN DATA',
}

/** The slice of the command a hop refers to, for showing what it points at. */
function excerpt(command: string, span: { start: number; end: number }) {
  const text = command.slice(span.start, span.end).replace(/\s+/g, ' ')
  return text.length > 60 ? text.slice(0, 57) + '…' : text
}

function Flow({ flow, command, index }: { flow: FlowView; command: string; index: number }) {
  return (
    <li className={`flow flow-${flow.outcome}`}>
      <div className="flow-head">
        <span className="flow-index">[{index + 1}]</span>
        <code>{flow.origin.label}</code>
        <span className={`badge badge-${flow.outcome}`}>{outcomeLabel[flow.outcome]}</span>
      </div>
      <p className="muted why">{flow.origin.why}</p>
      <ol className="hops">
        {flow.steps.map((step, i) => (
          <li key={i}>
            <span className="hop-kind">{step.kind}</span>
            <span className="hop-label">{step.label}</span>
            <code className="hop-span" title={`bytes ${step.span.start}–${step.span.end}`}>
              {excerpt(command, step.span)}
            </code>
          </li>
        ))}
      </ol>
    </li>
  )
}

export function Explanation({ assessment }: { assessment: Assessment }) {
  const { flows, commands, command, notes } = assessment

  return (
    <>
      <h2>Data flow</h2>
      {flows.length === 0 ? (
        <p className="muted">No sensitive data reached anywhere it could be observed.</p>
      ) : (
        <ol className="flows">
          {flows.map((f, i) => (
            <Flow key={i} flow={f} command={command} index={i} />
          ))}
        </ol>
      )}

      <h2>Commands</h2>
      <p className="muted">
        Two of the three deny rules turn on whether the knowledge base accounted for
        every part of a command, so what it did and did not recognise travels with the
        verdict.
      </p>
      <table className="coverage">
        <thead>
          <tr>
            <th>command</th>
            <th>coverage</th>
            <th>data</th>
          </tr>
        </thead>
        <tbody>
          {commands.map((c, i) => (
            <tr key={i}>
              <td>
                <code>{c.name}</code>
              </td>
              <td>
                {c.computed ? (
                  <span className="gap">forbidden: name from {c.computed}</span>
                ) : !c.known ? (
                  <span className="gap">not in the knowledge base</span>
                ) : c.untrustedPath ? (
                  <span className="gap">untrusted path: {c.untrustedPath}</span>
                ) : c.gaps?.length ? (
                  <span className="gap">unknown flags: {c.gaps.join(' ')}</span>
                ) : (
                  <span className="ok">fully understood</span>
                )}
              </td>
              <td className="muted">
                {c.receives ? 'receives sensitive data' : 'nothing sensitive enters'}
                {c.emits ? `, emits to ${c.emits}` : ''}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {notes && notes.length > 0 && (
        <>
          <h2>Not traced</h2>
          <ul className="notes">
            {notes.map((n, i) => (
              <li key={i} className="muted">
                {n.text}
              </li>
            ))}
          </ul>
        </>
      )}
    </>
  )
}
