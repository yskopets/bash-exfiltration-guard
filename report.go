package main

// Rendering an assessment for a terminal.
//
// This is the human-readable counterpart to api.go: the same analysis, shaped
// for reading rather than for parsing.

import (
	"fmt"
	"io"
	"strings"
)

// maxReported caps the per-command coverage listing. Real commands run to tens
// of kilobytes with dozens of stages; an unbounded listing is least readable
// exactly where it matters most.
const (
	maxCommandsReported = 12
	maxArgsReported     = 10
)

func report(w io.Writer, src string, a *Analyzer, verdict Verdict, reasons []string) {
	fmt.Fprintf(w, "command\n  %s\n\n", src)
	reportCoverage(w, a)
	reportFlows(w, src, a)

	if len(a.Notes) > 0 {
		fmt.Fprintf(w, "not traced\n")
		for _, n := range a.Notes {
			fmt.Fprintf(w, "  - %s\n      %s\n", n.Text, place(src, n.Span))
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "verdict\n  %s\n", verdict)
	fmt.Fprintf(w, "    (knowledge base: %s)\n", a.kb.Source)
	for _, r := range reasons {
		fmt.Fprintf(w, "    - %s\n", r)
	}
	if verdict == Allow && hasAuthFinding(a) {
		fmt.Fprintf(w, "  caveat: destination hosts are not modelled, so a credential sent to an\n"+
			"          untrusted host is indistinguishable from one sent to a trusted host.\n")
	}
}

// reportCoverage answers the question the verdict rests on: which parts of
// this command does the knowledge base actually account for?
func reportCoverage(w io.Writer, a *Analyzer) {
	fmt.Fprintf(w, "commands\n")
	if len(a.Uses) == 0 {
		fmt.Fprintf(w, "  (none)\n\n")
		return
	}
	for i, u := range a.Uses {
		if i == maxCommandsReported {
			fmt.Fprintf(w, "  ... and %d more\n", len(a.Uses)-i)
			break
		}
		fmt.Fprintf(w, "  [%d] %-38s %s\n", i+1, truncate(u.Name, 38), coverageLabel(u))
		for j, arg := range u.Args {
			if j == maxArgsReported {
				fmt.Fprintf(w, "        ... and %d more arguments\n", len(u.Args)-j)
				break
			}
			mark := " "
			if !arg.Known {
				mark = "!"
			}
			slot := ""
			if arg.Slot != "" {
				slot = "-> " + arg.Slot + " slot"
			}
			fmt.Fprintf(w, "      %s %-32s %-22s %s\n", mark, truncate(arg.Text, 32), arg.Role, slot)
		}
		fmt.Fprintf(w, "      %s\n", dataLabel(u))
	}
	fmt.Fprintln(w)
}

func coverageLabel(u CommandUse) string {
	switch {
	case u.Computed != "":
		return "FORBIDDEN: name from " + u.Computed
	case !u.Known:
		return "NOT IN KNOWLEDGE BASE"
	case u.UntrustedPath != "":
		return "UNTRUSTED PATH: " + u.UntrustedPath
	case len(u.Gaps) > 0:
		return "UNKNOWN FLAGS: " + strings.Join(u.Gaps, " ")
	}
	return "fully understood"
}

func dataLabel(u CommandUse) string {
	parts := []string{}
	if u.Receives {
		parts = append(parts, "receives sensitive data")
	} else {
		parts = append(parts, "no sensitive data enters here")
	}
	if u.Emits != "" {
		parts = append(parts, "emits to "+u.Emits)
	}
	return strings.Join(parts, ", ")
}

func reportFlows(w io.Writer, src string, a *Analyzer) {
	if len(a.Findings) == 0 {
		fmt.Fprintf(w, "data flow\n  no sensitive data reached a command that emits it\n\n")
		return
	}
	fmt.Fprintf(w, "data flow\n")
	for i, f := range a.Findings {
		fmt.Fprintf(w, "  [%d] %s\n", i+1, f.Flow.Origin)
		fmt.Fprintf(w, "      %s\n", f.Flow.Why)
		fmt.Fprintf(w, "      %s\n", place(src, f.Flow.Span))
		for _, s := range f.Flow.Steps {
			fmt.Fprintf(w, "        -> %-46s %s\n", s.Desc, place(src, s.Span))
		}
		label := "INTENDED USE"
		switch {
		case f.Unresolved:
			label = "UNKNOWN DATA"
		case exposingSlot(f.Slot):
			label = "EXPOSED"
		}
		fmt.Fprintf(w, "      %s: reaches %s\n", label, f.Emits)
		fmt.Fprintf(w, "      %s slot -- %s\n\n", f.Slot, f.Slot.Desc())
	}
}

func hasAuthFinding(a *Analyzer) bool {
	for _, f := range a.Findings {
		if f.Slot == SlotAuth && !f.Unresolved {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

// place renders a span as the source text it covers plus its byte offsets, so
// every line of the report can be checked against the original command.
func place(src string, s Span) string {
	if int(s.End) > len(src) || s.Start > s.End {
		return fmt.Sprintf("(%s)", s)
	}
	return fmt.Sprintf("`%s` (%s)", truncate(src[s.Start:s.End], 46), s)
}
