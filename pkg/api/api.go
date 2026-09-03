package api

// The wire contract.
//
// One Assessment type serves both `guard assess --json` and the HTTP API, so
// the contract is defined and tested once and a caller can move between them
// without changing its parser.
//
// These types are a projection of what the analyzer already computed -- they
// re-run nothing. What they add is machine-readability: the analyzer's prose
// ("captured by command substitution") is kept for people, and a `kind` is
// carried alongside it for callers that need to switch on the hop rather than
// read it.

import (
	"fmt"
	"strings"

	"guard/pkg/analyze"
	"guard/pkg/knowledge"
)

// Assessment is the response to "should this command run?".
type Assessment struct {
	Command       string `json:"command"`
	Verdict       string `json:"verdict"` // ALLOW | DENY
	KnowledgeBase string `json:"knowledgeBase"`

	// Parsed is false when the command is not valid shell. The verdict is
	// then DENY -- data flow through an unparsable command is unknown, and
	// unknown is never an allow -- and ParseError says why.
	Parsed     bool   `json:"parsed"`
	ParseError string `json:"parseError,omitempty"`

	// Message is the whole explanation as plain text, for a caller that just
	// wants something to print. Reasons is the same content as a list.
	Message string   `json:"message"`
	Reasons []string `json:"reasons"`

	// Commands is the per-command coverage record: which parts of the command
	// the knowledge base accounted for. This is what the verdict's second and
	// third clauses rest on, so it travels with the verdict.
	Commands []CommandView `json:"commands"`

	// Flows are the narrative paths, in order, each hop carrying a span into
	// the original command so a UI can highlight it.
	Flows []FlowView `json:"flows"`

	// Graph is the same information deduplicated into nodes and edges, for
	// drawing. Two flows through one variable converge on one node here,
	// where in Flows they each repeat it.
	Graph GraphView `json:"graph"`

	Notes []NoteView `json:"notes,omitempty"`
}

type CommandView struct {
	Name          string       `json:"name"`
	Span          analyze.Span `json:"span"`
	Known         bool         `json:"known"`
	Understood    bool         `json:"understood"`
	Receives      bool         `json:"receives"`
	Emits         string       `json:"emits,omitempty"`
	Gaps          []string     `json:"gaps,omitempty"`
	UntrustedPath string       `json:"untrustedPath,omitempty"`
	Computed      string       `json:"computed,omitempty"`
	Args          []ArgView    `json:"args,omitempty"`
}

type ArgView struct {
	Text  string       `json:"text"`
	Span  analyze.Span `json:"span"`
	Role  string       `json:"role"`
	Slot  string       `json:"slot,omitempty"`
	Known bool         `json:"known"`
}

type FlowView struct {
	Origin  OriginView `json:"origin"`
	Steps   []StepView `json:"steps"`
	Outcome string     `json:"outcome"` // exposed | intended-use | unresolved
}

type OriginView struct {
	Label string       `json:"label"`
	Kind  string       `json:"kind"`
	Why   string       `json:"why"`
	Span  analyze.Span `json:"span"`
}

type StepView struct {
	Kind  string       `json:"kind"`
	Label string       `json:"label"`
	Span  analyze.Span `json:"span"`
	Slot  string       `json:"slot,omitempty"`
	Emits string       `json:"emits,omitempty"`
}

type NoteView struct {
	Text string       `json:"text"`
	Span analyze.Span `json:"span"`
}

// ------------------------------------------------------------------ graph

type GraphView struct {
	Nodes []NodeView `json:"nodes"`
	Edges []EdgeView `json:"edges"`
}

type NodeView struct {
	ID    string       `json:"id"`
	Kind  string       `json:"kind"` // source | variable | transform | sink
	Label string       `json:"label"`
	Span  analyze.Span `json:"span"`
	Slot  string       `json:"slot,omitempty"`
	Emits string       `json:"emits,omitempty"`
}

type EdgeView struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

// Outcomes, matching the three labels the terminal prints.
const (
	OutcomeExposed     = "exposed"
	OutcomeIntendedUse = "intended-use"
	OutcomeUnresolved  = "unresolved"
)

// ------------------------------------------------------------- building

// NewAssessment projects a completed analysis onto the wire types.
func NewAssessment(src string, a *analyze.Analyzer, verdict analyze.Verdict, reasons []string) Assessment {
	as := Assessment{
		Command:       src,
		Verdict:       string(verdict),
		KnowledgeBase: a.Base().Source,
		Parsed:        true,
		Reasons:       reasons,
		Message:       message(verdict, reasons),
		Commands:      commandViews(a),
		Flows:         flowViews(a),
	}
	as.Graph = buildGraph(as.Flows)
	for _, n := range a.Notes {
		as.Notes = append(as.Notes, NoteView{Text: n.Text, Span: n.Span})
	}
	return as
}

// UnparsableAssessment is the result for a command that is not valid shell.
// It is a verdict, not an error: the data flow is unknown, and unknown is
// never an allow.
func UnparsableAssessment(src string, kb *knowledge.Base, err error) Assessment {
	reason := "the command cannot be parsed, so its data flow is unknown: " + err.Error()
	return Assessment{
		Command:       src,
		Verdict:       string(analyze.Deny),
		KnowledgeBase: kb.Source,
		Parsed:        false,
		ParseError:    err.Error(),
		Reasons:       []string{reason},
		Message:       message(analyze.Deny, []string{reason}),
		Commands:      []CommandView{},
		Flows:         []FlowView{},
		Graph:         GraphView{Nodes: []NodeView{}, Edges: []EdgeView{}},
	}
}

func message(verdict analyze.Verdict, reasons []string) string {
	var b strings.Builder
	b.WriteString(string(verdict))
	for _, r := range reasons {
		b.WriteString("\n  - ")
		b.WriteString(r)
	}
	return b.String()
}

func commandViews(a *analyze.Analyzer) []CommandView {
	out := make([]CommandView, 0, len(a.Uses))
	for _, u := range a.Uses {
		cv := CommandView{
			Name:          u.Name,
			Span:          u.Span,
			Known:         u.Known,
			Understood:    u.Understood(),
			Receives:      u.Receives,
			Emits:         u.Emits,
			Gaps:          u.Gaps,
			UntrustedPath: u.UntrustedPath,
			Computed:      u.Computed,
		}
		for _, arg := range u.Args {
			cv.Args = append(cv.Args, ArgView{
				Text: arg.Text, Span: arg.Span, Role: arg.Role,
				Slot: arg.Slot, Known: arg.Known,
			})
		}
		out = append(out, cv)
	}
	return out
}

func flowViews(a *analyze.Analyzer) []FlowView {
	out := make([]FlowView, 0, len(a.Findings))
	for _, f := range a.Findings {
		fv := FlowView{
			Origin: OriginView{
				Label: f.Flow.Origin,
				Kind:  string(f.Flow.Kind),
				Why:   f.Flow.Why,
				Span:  f.Flow.Span,
			},
			Outcome: outcomeOf(f),
		}
		for i, s := range f.Flow.Steps {
			sv := StepView{Kind: string(s.Kind), Label: s.Desc, Span: s.Span}
			// The last hop is the one that reached the sink, so it carries
			// the slot and destination.
			if i == len(f.Flow.Steps)-1 {
				sv.Slot, sv.Emits = f.SlotName, f.Emits
			}
			fv.Steps = append(fv.Steps, sv)
		}
		out = append(out, fv)
	}
	return out
}

func outcomeOf(f analyze.Finding) string {
	switch {
	case f.Unresolved:
		return OutcomeUnresolved
	case f.Slot.Exposes():
		return OutcomeExposed
	}
	return OutcomeIntendedUse
}

// buildGraph deduplicates the paths into nodes and edges.
//
// The point is convergence. `X=$(gh auth token); curl -H "...$X" -d "$X" ...`
// is two flows, and rendering them as two separate chains would draw the same
// credential and the same variable twice. Keying nodes on kind plus label
// collapses them, so the picture shows one source feeding one variable that
// feeds two sinks -- which is what actually happens.
func buildGraph(flows []FlowView) GraphView {
	g := GraphView{Nodes: []NodeView{}, Edges: []EdgeView{}}
	byKey := map[string]string{} // node key -> node id
	edgeSeen := map[string]bool{}

	node := func(kind, label string, span analyze.Span, slot, emits string) string {
		key := kind + "\x00" + label
		if id, ok := byKey[key]; ok {
			return id
		}
		id := fmt.Sprintf("n%d", len(g.Nodes)+1)
		byKey[key] = id
		g.Nodes = append(g.Nodes, NodeView{
			ID: id, Kind: kind, Label: label, Span: span, Slot: slot, Emits: emits,
		})
		return id
	}

	edge := func(from, to, kind string) {
		if from == to {
			return
		}
		key := from + "\x00" + to + "\x00" + kind
		if edgeSeen[key] {
			return
		}
		edgeSeen[key] = true
		g.Edges = append(g.Edges, EdgeView{From: from, To: to, Kind: kind})
	}

	for _, f := range flows {
		prev := node("source", f.Origin.Label, f.Origin.Span, "", "")
		for _, s := range f.Steps {
			kind, label := nodeFor(s)
			if kind == "" {
				// A hop that does not deserve a node of its own -- a pipe is
				// an edge between two things, not a thing.
				continue
			}
			id := node(kind, label, s.Span, s.Slot, s.Emits)
			edge(prev, id, s.Kind)
			prev = id
		}
	}
	return g
}

// nodeFor maps a hop to the node it lands on, or "" when the hop is only an
// edge. Assignment and expansion both land on the variable, so a value stored
// and later read collapses to one node rather than two.
func nodeFor(s StepView) (kind, label string) {
	switch analyze.StepKind(s.Kind) {
	case analyze.StepAssignment, analyze.StepExpansion:
		return "variable", variableName(s.Label)
	case analyze.StepSink, analyze.StepRedirect:
		return "sink", sinkLabel(s.Label)
	case analyze.StepPassthrough, analyze.StepFileRead, analyze.StepPrintsArgs,
		analyze.StepUnknownCommand, analyze.StepComputedName, analyze.StepProcessSubstitution:
		return "transform", s.Label
	case analyze.StepCommandSubstitution, analyze.StepPipe, analyze.StepStdinRedirect, analyze.StepHereDocument:
		return "", ""
	}
	return "transform", s.Label
}

// variableName pulls "$TOKEN" out of "assigned to $TOKEN" / "expanded as
// $TOKEN", so both hops key to the same node.
func variableName(label string) string {
	if i := strings.LastIndex(label, "$"); i >= 0 {
		return label[i:]
	}
	return label
}

// sinkLabel pulls "curl -d" out of "used as curl -d (content slot)". The slot
// is already a field on the node, so repeating it in the label would only
// make two sinks that differ by slot look like different programs.
func sinkLabel(label string) string {
	label = strings.TrimPrefix(label, "used as ")
	label = strings.TrimPrefix(label, "consumed from stdin by ")
	label = strings.TrimPrefix(label, "sent as ")
	if i := strings.Index(label, " ("); i >= 0 {
		label = label[:i]
	}
	return label
}
