import { useCallback, useEffect, useState } from 'react'
import { assess, knowledge, type Assessment, type Knowledge } from './api'
import { examples } from './examples'
import { load, remember, save, type HistoryEntry } from './history'
import { Examples } from './components/Examples'
import { Explanation } from './components/Explanation'
import { Graph } from './components/Graph'
import { History } from './components/History'

export default function App() {
  const [command, setCommand] = useState(examples[0].command)
  const [assessed, setAssessed] = useState('')
  const [assessment, setAssessment] = useState<Assessment | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [base, setBase] = useState<Knowledge | null>(null)
  const [history, setHistory] = useState<HistoryEntry[]>(load)

  useEffect(() => {
    knowledge().then(setBase).catch(() => setBase(null))
  }, [])

  const run = useCallback(async (src: string) => {
    const trimmed = src.trim()
    if (!trimmed) return

    setCommand(src)
    setBusy(true)
    setError(null)
    try {
      const result = await assess(src)
      setAssessment(result)
      setAssessed(src)
      setHistory((prev) => {
        const next = remember(prev, {
          command: src,
          verdict: result.verdict,
          at: Date.now(),
        })
        save(next)
        return next
      })
    } catch (e) {
      setAssessment(null)
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }, [])

  const clearHistory = useCallback(() => {
    setHistory([])
    save([])
  }, [])

  return (
    <div className="page">
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

      <div className="layout">
        <aside className="col">
          <Examples current={assessed} onPick={run} />
        </aside>

        <main className="col-main">
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

        <aside className="col">
          <History
            entries={history}
            current={assessed}
            onPick={run}
            onClear={clearHistory}
          />
        </aside>
      </div>
    </div>
  )
}
