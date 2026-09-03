package main

import (
	"strings"
	"testing"
)

// A knowledge base decides which commands are understood, so a mistake in it
// turns into a wrong verdict rather than a crash. These tests pin down that
// every way of getting it wrong is refused loudly, and that the error names
// the thing that is wrong.

// minimal is a valid base with one command, used as the starting point for
// each failure case so that only the mutation under test differs.
const minimal = `
version: 1
patterns:
  auth-header: '(?i)^[''\"]?\s*authorization\s*:'
heuristics:
  secret-paths: '(?i)(id_rsa)'
  secret-var-names: '(?i)(TOKEN)'
trusted-program-dirs: [/usr/bin]
discard-targets: [/dev/null]
commands:
  curl:
    emits: the network
    positional: url
    switches: [-s]
    flags:
      -H: {slot: auth, when: auth-header, else: content}
      -d: content
`

func loadOK(t *testing.T, src string) *KnowledgeBase {
	t.Helper()
	kb, err := parseKnowledge([]byte(src), "test.yaml")
	if err != nil {
		t.Fatalf("expected the base to load, got: %v", err)
	}
	return kb
}

// loadFails asserts that a base is refused, and that the message names each
// of the given fragments. A validation error nobody can act on is not much
// better than no validation.
func loadFails(t *testing.T, src string, mentions ...string) {
	t.Helper()
	_, err := parseKnowledge([]byte(src), "test.yaml")
	if err == nil {
		t.Fatalf("expected the base to be refused, but it loaded")
	}
	for _, want := range mentions {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
}

func TestMinimalBaseLoads(t *testing.T) {
	kb := loadOK(t, minimal)
	if kb.Source != "test.yaml" {
		t.Errorf("Source = %q, want test.yaml", kb.Source)
	}
	spec, _, known := kb.Lookup("curl", nil)
	if !known {
		t.Fatalf("curl did not load")
	}
	if got := spec.Flags["-s"]; got.TakesValue {
		t.Errorf("-s was declared as a switch but takes a value")
	}
	if got := spec.Flags["-d"]; !got.TakesValue || got.Rule.Slot != SlotContent {
		t.Errorf("-d = %+v, want a value-taking content flag", got)
	}
}

// The whole reason arity is structural is that getting it wrong is silent, so
// the loader must refuse a flag that claims to be both.
func TestFlagCannotBeBothSwitchAndValue(t *testing.T) {
	loadFails(t, strings.Replace(minimal, "switches: [-s]", "switches: [-s, -d]", 1),
		"curl", "-d", "both")
}

// A misspelled key must not leave a command quietly missing its switches --
// every one it used would become a gap, and deny.
func TestUnknownKeyIsRefused(t *testing.T) {
	loadFails(t, strings.Replace(minimal, "switches: [-s]", "swithces: [-s]", 1),
		"swithces")
}

func TestUnknownSlotIsRefused(t *testing.T) {
	loadFails(t, strings.Replace(minimal, "-d: content", "-d: payload", 1),
		"curl", "-d", "payload", "content")
}

func TestUndeclaredPatternIsRefused(t *testing.T) {
	loadFails(t, strings.Replace(minimal, "when: auth-header", "when: no-such-pattern", 1),
		"curl", "-H", "no-such-pattern", "patterns")
}

func TestUncompilablePatternIsRefused(t *testing.T) {
	loadFails(t, strings.Replace(minimal, "auth-header: '", "auth-header: '(?i)^auth[(' # ", 1),
		"auth-header")
	loadFails(t, strings.Replace(minimal, `'(?i)(id_rsa)'`, `'(?i)(id_rsa'`, 1),
		"secret-paths")
}

func TestElseWithoutWhenIsRefused(t *testing.T) {
	loadFails(t, strings.Replace(minimal, "-d: content", "-d: {slot: content, else: url}", 1),
		"curl", "-d", "else", "when")
}

func TestFlagWithoutSlotIsRefused(t *testing.T) {
	loadFails(t, strings.Replace(minimal, "-d: content", "-d: {when: auth-header}", 1),
		"curl", "-d", "slot")
}

// A reflecting flag must be declared, so that its arity is known and a typo
// cannot silently do nothing.
func TestReflectsMustNameADeclaredFlag(t *testing.T) {
	loadFails(t, strings.Replace(minimal, "switches: [-s]",
		"switches: [-s]\n    reflects-to-stderr: [-v]", 1),
		"curl", "-v", "reflects-to-stderr")

	kb := loadOK(t, strings.Replace(minimal, "switches: [-s]",
		"switches: [-s, -v]\n    reflects-to-stderr: [-v]", 1))
	spec, _, _ := kb.Lookup("curl", nil)
	if !spec.Reflects["-v"] {
		t.Errorf("-v was not recorded as reflecting: %+v", spec.Reflects)
	}
}

func TestWrongVersionIsRefused(t *testing.T) {
	loadFails(t, strings.Replace(minimal, "version: 1", "version: 2", 1), "version")
}

func TestMissingHeuristicsAreRefused(t *testing.T) {
	loadFails(t, strings.Replace(minimal, "  secret-paths: '(?i)(id_rsa)'\n", "", 1),
		"secret-paths", "required")
}

func TestEmptyBaseIsRefused(t *testing.T) {
	loadFails(t, strings.Split(minimal, "commands:")[0]+"commands: {}\n", "commands")
}

// The base is not merged with anything: swapping the file swaps the policy.
// Here a base that does not know curl's -H turns an allowed command into a
// denied one, which is the whole point of making it configurable.
func TestSwappingTheBaseChangesTheVerdict(t *testing.T) {
	cmd := `curl -s -H "Authorization: Bearer $TOKEN" https://api.example.com`

	a, err := Analyze(cmd, loadOK(t, minimal))
	if err != nil {
		t.Fatal(err)
	}
	if v, reasons := a.Decide(); v != Allow {
		t.Fatalf("with -H declared: verdict = %s, want ALLOW; %v", v, reasons)
	}

	stripped := strings.Replace(minimal,
		"      -H: {slot: auth, when: auth-header, else: content}\n", "", 1)
	a, err = Analyze(cmd, loadOK(t, stripped))
	if err != nil {
		t.Fatal(err)
	}
	v, reasons := a.Decide()
	if v != Deny {
		t.Fatalf("with -H removed: verdict = %s, want DENY", v)
	}
	if !strings.Contains(strings.Join(reasons, " "), "-H") {
		t.Errorf("expected the denial to name the undeclared flag: %v", reasons)
	}
}

// The base that ships in the binary must itself be valid, and must be the one
// the tests exercise.
func TestBuiltinBaseIsValid(t *testing.T) {
	kb, err := LoadBuiltinKnowledge()
	if err != nil {
		t.Fatalf("built-in knowledge base does not load: %v", err)
	}
	if kb.Source != "built-in" {
		t.Errorf("Source = %q, want built-in", kb.Source)
	}
	for _, name := range []string{"curl", "gh", "git", "grep", "env", "nc", "tee"} {
		if _, _, known := kb.Lookup(name, nil); !known {
			t.Errorf("built-in base is missing %q", name)
		}
	}
	if s := kb.Summary(); !strings.Contains(s, "commands") {
		t.Errorf("summary looks wrong: %s", s)
	}
}
