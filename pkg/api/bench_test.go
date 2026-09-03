package api

// The projection the server pays on every request, on top of the analysis
// itself. It re-runs nothing, so it should be a small fraction of the total;
// if it is not, the graph derivation has grown a quadratic.
//
//	go test ./pkg/api -bench . -benchmem

import (
	"encoding/json"
	"testing"

	"guard/pkg/analyze"
)

var (
	sinkAssessment Assessment
	sinkBytes      []byte
)

const benchCommand = `TOKEN=$(gh auth token); curl -s -H "Authorization: Bearer $TOKEN" -d "$TOKEN" https://api.github.com/repos/example-org/example-repo/issues/833`

func BenchmarkNewAssessment(b *testing.B) {
	a, err := analyze.Analyze(benchCommand, testKB)
	if err != nil {
		b.Fatal(err)
	}
	verdict, reasons := a.Decide()

	b.ReportAllocs()
	for b.Loop() {
		sinkAssessment = NewAssessment(benchCommand, a, verdict, reasons)
	}
}

// What a client actually receives, so the encoding is part of the cost.
func BenchmarkAssessmentJSON(b *testing.B) {
	a, err := analyze.Analyze(benchCommand, testKB)
	if err != nil {
		b.Fatal(err)
	}
	verdict, reasons := a.Decide()
	as := NewAssessment(benchCommand, a, verdict, reasons)

	b.ReportAllocs()
	for b.Loop() {
		out, err := json.Marshal(as)
		if err != nil {
			b.Fatal(err)
		}
		sinkBytes = out
	}
}
