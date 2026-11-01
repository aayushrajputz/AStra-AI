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
