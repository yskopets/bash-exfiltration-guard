import { useEffect, useMemo } from 'react'
import {
  Background,
  Controls,
  ReactFlow,
  type Edge,
  type Node,
  MarkerType,
  Position,
  useNodesInitialized,
  useReactFlow,
} from '@xyflow/react'
import dagre from '@dagrejs/dagre'
import '@xyflow/react/dist/style.css'
import type { GraphView, NodeView } from '../api'

const WIDTH = 200
const HEIGHT = 52

// The API already deduplicates the graph, so two flows through one variable
// arrive as one node with two outgoing edges. All that is left is to place
// them, which dagre does; hand-placing a converging layout is where a bespoke
// renderer starts to hurt.
function layout(graph: GraphView): { nodes: Node[]; edges: Edge[]; height: number } {
  const g = new dagre.graphlib.Graph()
  g.setDefaultEdgeLabel(() => ({}))
  g.setGraph({ rankdir: 'LR', nodesep: 28, ranksep: 72 })

  graph.nodes.forEach((n) => g.setNode(n.id, { width: WIDTH, height: HEIGHT }))
  graph.edges.forEach((e) => g.setEdge(e.from, e.to))
  dagre.layout(g)

  const nodes: Node[] = graph.nodes.map((n) => {
    const placed = g.node(n.id)
    return {
      id: n.id,
      position: { x: placed.x - WIDTH / 2, y: placed.y - HEIGHT / 2 },
      data: { label: nodeLabel(n) },
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
      style: nodeStyle(n),
      // Declared so fitView can size the viewport on the first paint. Without
      // them React Flow has to measure the DOM first and fits to a guess,
      // which lands the graph at a fraction of the space it has.
      width: WIDTH,
      height: HEIGHT,
    }
  })

  const edges: Edge[] = graph.edges.map((e, i) => ({
    id: `e${i}`,
    source: e.from,
    target: e.to,
    label: e.kind,
    labelStyle: { fontSize: 10, fill: '#52525b' },
    style: { stroke: '#a1a1aa' },
    markerEnd: { type: MarkerType.ArrowClosed, color: '#a1a1aa' },
  }))

  // Size the frame to the diagram rather than to a guess. A fixed height
  // leaves a two-node graph floating in white space and crops a wide one.
  const rows = Math.max(1, (g.graph().height ?? HEIGHT) / (HEIGHT + 28))
  const height = Math.min(460, Math.max(150, Math.round(rows * (HEIGHT + 46)) + 56))

  return { nodes, edges, height }
}

function nodeLabel(n: NodeView) {
  const detail = n.slot ? `${n.kind} · ${n.slot} slot` : n.kind
  return (
    <div style={{ lineHeight: 1.35 }}>
      <div style={{ fontWeight: 600, fontSize: 12 }}>{n.label}</div>
      <div style={{ fontSize: 10, opacity: 0.7 }}>{detail}</div>
    </div>
  )
}

// A sink is where the verdict is decided, so it is the one that should catch
// the eye; an auth slot is the exception that gets a calmer colour.
function nodeStyle(n: NodeView): React.CSSProperties {
  const base: React.CSSProperties = {
    width: WIDTH,
    borderRadius: 8,
    borderWidth: 1,
    borderStyle: 'solid',
    padding: '8px 10px',
    fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
    textAlign: 'left',
  }
  switch (n.kind) {
    case 'source':
      return { ...base, background: '#fefce8', borderColor: '#eab308' }
    case 'variable':
      return { ...base, background: '#f4f4f5', borderColor: '#a1a1aa' }
    case 'sink':
      return n.slot === 'auth'
        ? { ...base, background: '#f0fdf4', borderColor: '#22c55e' }
        : { ...base, background: '#fef2f2', borderColor: '#ef4444' }
    default:
      return { ...base, background: '#fff', borderColor: '#d4d4d8' }
  }
}

// Refit once the nodes have been measured, and again whenever the graph
// changes. ReactFlow's own fitView prop runs before the container has been
// laid out, which leaves the diagram at a fraction of the space it has.
function FitView({ on }: { on: unknown }) {
  const initialized = useNodesInitialized()
  const { fitView } = useReactFlow()

  useEffect(() => {
    if (initialized) void fitView({ padding: 0.08, maxZoom: 1, duration: 0 })
  }, [initialized, on, fitView])

  return null
}

export function Graph({ graph }: { graph: GraphView }) {
  const { nodes, edges, height } = useMemo(() => layout(graph), [graph])

  if (graph.nodes.length === 0) {
    return <p className="muted">No data flow to draw.</p>
  }

  return (
    <div style={{ height, border: '1px solid #e4e4e7', borderRadius: 8 }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        proOptions={{ hideAttribution: true }}
        nodesDraggable
        nodesConnectable={false}
      >
        <FitView on={graph} />
        <Background gap={16} color="#f4f4f5" />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  )
}
