package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// guard maps the flow of security-sensitive data through a bash command.
//
//	guard '<command>'
//	echo '<command>' | guard
//	guard -json '<command>'
//
// It is a prototype. It reports what it can trace and says plainly what it
// cannot; it does not attempt a verdict on whether a command should run.

func main() {
	jsonOut := flag.Bool("json", false, "emit the flow graph as JSON")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: guard [-json] '<bash command>'\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	src := strings.Join(flag.Args(), " ")
	if strings.TrimSpace(src) == "" {
		b, err := io.ReadAll(os.Stdin)
		if err != nil || strings.TrimSpace(string(b)) == "" {
			flag.Usage()
			os.Exit(2)
		}
		src = string(b)
	}
	src = strings.TrimRight(src, "\n")

	a, err := Analyze(src)
	if err != nil {
		// A command that cannot be parsed has unknown data flow. Saying so is
		// the honest result; claiming "no flows found" would not be.
		fmt.Fprintf(os.Stderr, "cannot parse command, so its data flow is unknown:\n  %v\n", err)
		os.Exit(3)
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"command":  src,
			"findings": a.Findings,
			"notes":    a.Notes,
		})
		return
	}
	report(os.Stdout, src, a)
}

// exposing reports whether a slot puts data somewhere it can be observed by
// someone who should not see it. An Authorization header is not exposure --
// that is what the credential is for -- so it is reported separately.
func exposing(s Slot) bool { return s != SlotAuth && s != SlotNone }

func report(w io.Writer, src string, a *Analyzer) {
	fmt.Fprintf(w, "command\n  %s\n\n", src)

	if len(a.Findings) == 0 {
		fmt.Fprintf(w, "data flow\n  no sensitive data reached a command that emits it\n\n")
	} else {
		fmt.Fprintf(w, "data flow\n")
	}

	for i, f := range a.Findings {
		fmt.Fprintf(w, "  [%d] %s\n", i+1, f.Flow.Origin)
		fmt.Fprintf(w, "      %s\n", f.Flow.Why)
		fmt.Fprintf(w, "      %s\n", place(src, f.Flow.Span))
		for _, s := range f.Flow.Steps {
			fmt.Fprintf(w, "        -> %-46s %s\n", s.Desc, place(src, s.Span))
		}
		verdict := "INTENDED USE"
		if exposing(f.Slot) {
			verdict = "EXPOSED"
		}
		fmt.Fprintf(w, "      %s: reaches %s\n", verdict, f.Emits)
		fmt.Fprintf(w, "      %s slot -- %s\n\n", f.Slot, f.Slot.Desc())
	}

	if len(a.Notes) > 0 {
		fmt.Fprintf(w, "limits of this analysis\n")
		for _, n := range a.Notes {
			fmt.Fprintf(w, "  - %s\n      %s\n", n.Text, place(src, n.Span))
		}
		fmt.Fprintln(w)
	}

	var exposed, intended int
	for _, f := range a.Findings {
		if exposing(f.Slot) {
			exposed++
		} else {
			intended++
		}
	}
	fmt.Fprintf(w, "summary\n  %d flow(s) traced to a sink: %d exposed, %d intended use\n",
		len(a.Findings), exposed, intended)
	if len(a.Notes) > 0 {
		fmt.Fprintf(w, "  %d part(s) of the command could not be fully traced (see above)\n", len(a.Notes))
	}
}

// place renders a span as the source text it covers plus its byte offsets, so
// every line of the report can be checked against the original command.
func place(src string, s Span) string {
	if int(s.End) > len(src) || s.Start > s.End {
		return fmt.Sprintf("(%s)", s)
	}
	text := src[s.Start:s.End]
	if len(text) > 46 {
		text = text[:43] + "..."
	}
	return fmt.Sprintf("`%s` (%s)", text, s)
}
