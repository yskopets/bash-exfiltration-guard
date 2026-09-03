package knowledge

// The CLI pays this once per invocation. As a PreToolUse hook that is once per
// command the agent runs, so it is part of the per-command cost even though
// the server pays it only at startup.
//
//	go test ./pkg/knowledge -bench . -benchmem

import "testing"

var sinkBase *Base

func BenchmarkLoadBuiltin(b *testing.B) {
	b.ReportAllocs()
	b.SetBytes(int64(len(builtinKnowledge)))
	for b.Loop() {
		kb, err := LoadBuiltin()
		if err != nil {
			b.Fatal(err)
		}
		sinkBase = kb
	}
}

// Lookup runs several times per command, so it wants to stay cheap.
func BenchmarkLookup(b *testing.B) {
	kb, err := LoadBuiltin()
	if err != nil {
		b.Fatal(err)
	}
	cases := []struct {
		name string
		argv []string
	}{
		{"top-level", []string{"curl"}},
		{"subcommand", []string{"gh", "auth", "token"}},
		{"unknown", []string{"mystery-tool"}},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_, _, _ = kb.Lookup(c.argv[0], c.argv[1:])
			}
		})
	}
}
