// The wire contract, mirroring pkg/api/api.go.
//
// Hand-written and therefore hand-maintained: a field added there has to be
// added here. Generating this from the Go types is worth doing once the
// contract stops moving.

export type Span = { start: number; end: number }

export type Verdict = 'ALLOW' | 'DENY'

/** Matches api.OutcomeExposed / IntendedUse / Unresolved. */
export type Outcome = 'exposed' | 'intended-use' | 'unresolved'

export type OriginView = {
  label: string
  kind: string
  why: string
  span: Span
}

export type StepView = {
  kind: string
  label: string
  span: Span
  slot?: string
  emits?: string
}

export type FlowView = {
  origin: OriginView
  steps: StepView[]
  outcome: Outcome
}

export type ArgView = {
  text: string
  span: Span
  role: string
  slot?: string
  known: boolean
}

export type CommandView = {
  name: string
  span: Span
  known: boolean
  understood: boolean
  receives: boolean
  emits?: string
  gaps?: string[]
  untrustedPath?: string
  computed?: string
  args?: ArgView[]
}

export type NodeView = {
  id: string
  kind: 'source' | 'variable' | 'transform' | 'sink'
  label: string
  span: Span
  slot?: string
  emits?: string
}

export type EdgeView = { from: string; to: string; kind: string }

export type GraphView = { nodes: NodeView[]; edges: EdgeView[] }

export type Assessment = {
  command: string
  verdict: Verdict
  knowledgeBase: string
  parsed: boolean
  parseError?: string
  message: string
  reasons: string[]
  commands: CommandView[]
  flows: FlowView[]
  graph: GraphView
  notes?: { text: string; span: Span }[]
}

export type Knowledge = {
  source: string
  summary: string
  commands: number
  subcommands: number
}

async function json<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const body = await res.text()
    let message = body
    try {
      message = (JSON.parse(body) as { error?: string }).error ?? body
    } catch {
      // not JSON; the raw body is the best we have
    }
    throw new Error(`${res.status}: ${message}`)
  }
  return res.json() as Promise<T>
}

export async function assess(command: string): Promise<Assessment> {
  return json<Assessment>(
    await fetch('/api/v1/assess', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ command }),
    }),
  )
}

export async function knowledge(): Promise<Knowledge> {
  return json<Knowledge>(await fetch('/api/v1/knowledge'))
}
