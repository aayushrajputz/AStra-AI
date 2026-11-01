package policy

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/astra-ai/astra/internal/analyzer"
	"github.com/astra-ai/astra/internal/diff"
)

func TestLoadDefaultsFailOnBreaking(t *testing.T) {
	config, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got := config.FailOnSeverities(); !reflect.DeepEqual(got, []string{"breaking"}) {
		t.Fatalf("default fail-on = %#v, want [breaking]", got)
	}
}

func TestLoadFiltersIgnoredPathsAndReadsPolicy(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, ".astrarc.json")
	raw := `{
  "ignored_paths": ["docs/**", "**/*.generated.ts"],
  "fail_on": ["breaking", "uncertain"],
  "severity_rules": {"breaking": "critical", "potential": "warning"}
}`
	if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if !config.IsIgnored("docs/api.md") || !config.IsIgnored("src/generated/users.generated.ts") ||
		config.IsIgnored("src/users.ts") {
		t.Fatalf("ignored path matching incorrect")
	}
	if got := config.FailOnSeverities(); !reflect.DeepEqual(got, []string{"breaking", "uncertain"}) {
		t.Fatalf("fail-on = %#v", got)
	}
	if config.DisplaySeverity("breaking") != "critical" || config.DisplaySeverity("non-breaking") != "non-breaking" {
		t.Fatalf("severity rule lookup incorrect")
	}
}

func TestFilterChangesPreservesNonIgnoredFiles(t *testing.T) {
	config := Config{IgnoredPaths: []string{"docs/**"}}
	changes := []diff.File{
		{Path: "docs/api.md", Status: diff.Modified},
		{Path: "src/users.ts", Status: diff.Modified},
	}
	filtered := config.FilterChanges(changes)
	if len(filtered) != 1 || filtered[0].Path != "src/users.ts" {
		t.Fatalf("filtered changes = %#v", filtered)
	}
}

func TestViolationsHonorFailOnAndSeverityLabels(t *testing.T) {
	config := Config{
		FailOn:        []string{"breaking", "uncertain"},
		SeverityRules: map[string]string{"breaking": "critical"},
	}
	report := &analyzer.Report{AffectedRoutes: []analyzer.RouteImpact{
		{Route: analyzer.Route{Method: "POST", Path: "/users"}, Reason: "field removed", Severity: "breaking"},
		{Route: analyzer.Route{Method: "GET", Path: "/health"}, Reason: "possible impact", Severity: "potential"},
	}}
	violations := config.Violations(report)
	if len(violations) != 1 || violations[0] != "POST /users: field removed (critical)" {
		t.Fatalf("violations = %#v", violations)
	}
}

func TestExplicitEmptyFailOnDisablesGate(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".astrarc.json"), []byte(`{"fail-on":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := config.FailOnSeverities(); len(got) != 0 {
		t.Fatalf("explicit empty fail-on = %#v, want empty", got)
	}
}

func TestLoadRejectsInvalidPolicyValues(t *testing.T) {
	tests := []string{
		`{"fail_on":["unknown"]}`,
		`{"fail_on":null}`,
		`{"ignored_paths":["src/["]}`,
		`{"severity_rules":{"breaking":"urgent"}}`,
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, ".astrarc.json"), []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(root); err == nil {
				t.Fatal("expected invalid policy to return an explicit error")
			}
		})
	}
}

func TestLoadMergeGatePolicyAndPerRouteSeverity(t *testing.T) {
	root := t.TempDir()
	raw := `{"fail_on":"unresolved-breaking","ignore_paths":["docs/**"],"route_severity":{"POST /transfer":"any-breaking"},"allow_heuristic_failures":false}`
	if err := os.WriteFile(filepath.Join(root, ".astrarc.json"), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if config.GateMode != "unresolved-breaking" || !config.IsIgnored("docs/api.md") {
		t.Fatalf("merge policy was not loaded: %#v", config)
	}
	if config.RouteSeverity["POST /transfer"] != "any-breaking" || config.AllowHeuristicFailures {
		t.Fatalf("route policy/default heuristic behavior incorrect: %#v", config)
	}
}

func TestGateOnlyFailsUnresolvedBreakingAndActiveWaiverSuppresses(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".astrarc.json"), []byte(`{"fail_on":"unresolved-breaking"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".astra-waivers.json"), []byte(`{"waivers":[{"symbol":"TransferService.Move","reason":"temporary compatibility window","owner":"payments-team","expires":"2099-12-31"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	report := &analyzer.Report{AffectedRoutes: []analyzer.RouteImpact{
		{Route: analyzer.Route{Method: "POST", Path: "/transfer"}, Reason: "required param added", Severity: "breaking", Resolution: "resolved", Symbol: "TransferService.Move"},
		{Route: analyzer.Route{Method: "POST", Path: "/transfer"}, Reason: "required param added", Severity: "breaking", Resolution: "unresolved", Confidence: "exact", Symbol: "TransferService.Move"},
		{Route: analyzer.Route{Method: "GET", Path: "/status"}, Reason: "heuristic match", Severity: "breaking", Resolution: "needs-review", Confidence: "heuristic"},
	}}
	gate := config.Evaluate(report)
	if gate.Status != "pass" || len(gate.Violations) != 0 || len(gate.ActiveWaivers) != 1 {
		t.Fatalf("valid waiver or resolution policy failed: %#v", gate)
	}
}

func TestHeuristicBreakingNeedsOptInToFailAndStillRequiresUnresolvedCaller(t *testing.T) {
	config := Config{
		GateMode: "unresolved-breaking", AllowHeuristicFailures: true,
	}
	impact := analyzer.RouteImpact{
		Route:  analyzer.Route{Method: "POST", Path: "/transfer"},
		Reason: "required argument added", Severity: "breaking",
		Resolution: "unresolved", Confidence: "heuristic",
	}
	failed := config.Evaluate(&analyzer.Report{AffectedRoutes: []analyzer.RouteImpact{impact}})
	if failed.Status != "fail" || len(failed.Violations) != 1 {
		t.Fatalf("opted-in unresolved heuristic finding did not fail: %#v", failed)
	}
	impact.Resolution = "resolved"
	passed := config.Evaluate(&analyzer.Report{AffectedRoutes: []analyzer.RouteImpact{impact}})
	if passed.Status != "pass" || len(passed.Violations) != 0 {
		t.Fatalf("resolved heuristic finding failed the gate: %#v", passed)
	}
}

func TestActiveWaiverSuppressesLegacyFailOnFinding(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".astrarc.json"), []byte(`{"fail_on":["breaking"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".astra-waivers.json"), []byte(`{"waivers":[{"route":"POST /transfer","reason":"migration window","owner":"payments","expires":"2099-12-31"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	gate := config.Evaluate(&analyzer.Report{AffectedRoutes: []analyzer.RouteImpact{
		{Route: analyzer.Route{Method: "POST", Path: "/transfer"}, Severity: "breaking", Reason: "required argument added"},
	}})
	if gate.Status != "pass" || len(gate.Violations) != 0 || len(gate.ActiveWaivers) != 1 {
		t.Fatalf("active waiver did not suppress legacy gate finding: %#v", gate)
	}
}

func TestExpiredWaiverFailsGate(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".astrarc.json"), []byte(`{"fail_on":"never"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".astra-waivers.json"), []byte(`{"waivers":[{"route":"POST /transfer","reason":"temporary exception","owner":"payments-team","expires":"2000-01-01"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	gate := config.Evaluate(&analyzer.Report{})
	if gate.Status != "fail" || len(gate.Violations) == 0 {
		t.Fatalf("expired waiver did not fail gate: %#v", gate)
	}
}
