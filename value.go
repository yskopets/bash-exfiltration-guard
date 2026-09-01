package main

import "fmt"

// This file defines what "data" means to the analyzer.
//
// The analyzer never tries to compute the actual string a shell word would
// expand to -- that would require running the command. Instead every word
// evaluates to a Value: the set of sensitive Flows the word carries, plus a
// record of anything that could not be resolved.

// Span is a byte range in the original command text. Every node in the flow
// graph carries one, so a report can always point back at the source.
type Span struct {
	Start uint `json:"start"`
	End   uint `json:"end"`
}

func (s Span) String() string { return fmt.Sprintf("%d:%d", s.Start, s.End) }

// Step is one hop that data takes: out of a command substitution, into a
// variable, back out of that variable, into a command argument.
type Step struct {
	Desc string `json:"desc"`
	Span Span   `json:"span"`
}

// Flow is one complete path taken by a piece of sensitive data, from the
// place it originated to wherever it currently sits. A Flow is the edge list
// of the data flow graph; the graph is kept as paths rather than as a node
// set because a path is what a human needs to read.
type Flow struct {
	Origin string `json:"origin"` // the source text, e.g. "gh auth token"
	Why    string `json:"why"`    // why that source is sensitive
	Span   Span   `json:"span"`   // where the origin sits in the command
	Steps  []Step `json:"steps"`
}

// then returns a copy of f with one more hop appended.
//
// The copy is deliberate. Two words that both read $TOKEN each continue the
// same stored Flow, and appending in place would let the first one's history
// leak into the second's.
func (f Flow) then(desc string, span Span) Flow {
	steps := make([]Step, len(f.Steps), len(f.Steps)+1)
	copy(steps, f.Steps)
	f.Steps = append(steps, Step{Desc: desc, Span: span})
	return f
}

// Unknown records a command the knowledge base has never heard of.
//
// An unknown command is never treated as safe. Whatever it prints is assumed
// to be at least as sensitive as whatever it was handed, and an unknown
// command that receives sensitive data is reported rather than ignored.
type Unknown struct {
	Command string `json:"command"`
	Reason  string `json:"reason"`
	Span    Span   `json:"span"`
}

// Value is what a shell word, or a command's stdout, evaluates to.
type Value struct {
	Flows    []Flow    `json:"flows,omitempty"`
	Unknowns []Unknown `json:"unknowns,omitempty"`
}

func (v Value) empty() bool { return len(v.Flows) == 0 && len(v.Unknowns) == 0 }

// then advances every flow in the value by one hop.
func (v Value) then(desc string, span Span) Value {
	out := Value{Unknowns: v.Unknowns}
	for _, f := range v.Flows {
		out.Flows = append(out.Flows, f.then(desc, span))
	}
	return out
}

// union merges values, which is what happens when a word is built out of
// several parts ("Bearer $TOKEN") or a command reads several inputs.
func union(vs ...Value) Value {
	var out Value
	for _, v := range vs {
		out.Flows = append(out.Flows, v.Flows...)
		out.Unknowns = append(out.Unknowns, v.Unknowns...)
	}
	return out
}
