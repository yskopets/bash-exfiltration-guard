import { useCallback, useEffect, useState } from 'react'
import { assess, knowledge, type Assessment, type Knowledge } from './api'
import { examples } from './examples'
import { Explanation } from './components/Explanation'
import { Graph } from './components/Graph'

export default function App() {
  const [command, setCommand] = useState(examples[0].command)
  const [assessment, setAssessment] = useState<Assessment | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [base, setBase] = useState<Knowledge | null>(null)

  useEffect(() => {
    knowledge().then(setBase).catch(() => setBase(null))
  }, [])

  const run = useCallback(async (src: string) => {
    if (!src.trim()) return
    setBusy(true)
    setError(null)
    try {
      setAssessment(await assess(src))
    } catch (e) {
      setAssessment(null)
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }, [])

  return (
    <main>
      <header>
        <h1>guard</h1>
        <p>
          Paste a bash command. <strong>guard</strong> parses it, traces where
          security-sensitive data in it comes from and where it ends up, and decides
          whether it should run.
        </p>
        <p className="muted">
          It never executes what you give it — it walks the syntax tree, and that is all.
          {base && (
            <>
              {' '}Assessed against knowledge base <code>{base.source}</code>, which
              declares {base.commands} commands.
            </>
          )}
        </p>
      </header>

      <section>
        <h2>Examples</h2>
        <div className="examples">
          {examples.map((ex) => (
            <button
              key={ex.title}
              className="example"
              onClick={() => {
                setCommand(ex.command)
                void run(ex.command)
              }}
            >
              <span className="example-title">{ex.title}</span>
              <span className="example-note">{ex.note}</span>
            </button>
          ))}
        </div>
      </section>

      <section>
        <h2>Command</h2>
        <textarea
          value={command}
          spellCheck={false}
          rows={4}
          onChange={(e) => setCommand(e.target.value)}
          onKeyDown={(e) => {
            if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') void run(command)
          }}
        />
        <div className="actions">
          <button className="primary" onClick={() => void run(command)} disabled={busy}>
            {busy ? 'Assessing…' : 'Assess'}
          </button>
          <span className="muted hint">⌘/Ctrl + Enter</span>
        </div>
      </section>

      {error && (
        <section className="error">
          <h2>Request failed</h2>
          <pre>{error}</pre>
        </section>
      )}

      {assessment && (
        <>
          <section>
            <h2>Verdict</h2>
            <div className={`verdict verdict-${assessment.verdict.toLowerCase()}`}>
              <span className="verdict-word">{assessment.verdict}</span>
              <ul>
                {assessment.reasons.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            </div>
            {!assessment.parsed && (
              <p className="muted">
                The command is not valid shell, so its data flow is unknown — and
                unknown is never an allow.
              </p>
            )}
          </section>

          <section>
            <Explanation assessment={assessment} />
          </section>

          <section>
            <h2>Visualization</h2>
            <Graph graph={assessment.graph} />
          </section>
        </>
      )}
    </main>
  )
}
