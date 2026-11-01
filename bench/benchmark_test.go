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
	if metrics.TruePositives != 2 || metrics.FalsePositives != 2 ||
		metrics.FalseNegatives != 1 || metrics.TrueNegatives != 3 || metrics.Warnings != 1 {
		t.Fatalf("unexpected baseline: %+v\n%s", metrics, output.String())
	}
	if !strings.Contains(output.String(), "~") || !strings.Contains(output.String(), "⚠") {
		t.Fatalf("benchmark output must show heuristic and dynamic uncertainty flags:\n%s", output.String())
	}
}
