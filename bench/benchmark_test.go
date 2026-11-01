package bench

import (
	"bytes"
	"strings"
	"testing"
)

func TestCuratedCommitCorpusBaseline(t *testing.T) {
	var output bytes.Buffer
	metrics, err := Run(&output)
	if err != nil {
		t.Fatal(err)
	}
	if metrics.TruePositives != 3 || metrics.FalsePositives != 1 ||
		metrics.FalseNegatives != 1 || metrics.TrueNegatives != 5 || metrics.Warnings != 1 {
		t.Fatalf("unexpected combined synthetic benchmark: %+v\n%s", metrics, output.String())
	}
	if !strings.Contains(output.String(), "~") || !strings.Contains(output.String(), "⚠") {
		t.Fatalf("benchmark output must show heuristic and dynamic uncertainty flags:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "go-gin-required-parameter") {
		t.Fatalf("benchmark output did not include the Go commit case:\n%s", output.String())
	}
}
