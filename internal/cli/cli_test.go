package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckReportsAffectedRouteFromGitDiff(t *testing.T) {
	t.Setenv("ASTRA_CACHE_DIR", filepath.Join(t.TempDir(), "cache"))
	root := createGitRepo(t)
	source := `function lookupUser() {
	return 1;
}
function getUser(req, res) {
	lookupUser();
}
app.get("/users", getUser);
`
	writeFile(t, root, "server.ts", source)
	git(t, root, "add", "server.ts")
	git(t, root, "-c", "user.name=AStra Test", "-c", "user.email=astra@example.invalid", "commit", "-m", "initial")

	source = strings.Replace(source, "return 1;", "return 2;", 1)
	writeFile(t, root, "server.ts", source)
	var output bytes.Buffer
	if err := runAt([]string{"check", "--json"}, &output, &bytes.Buffer{}, root); err != nil {
		t.Fatal(err)
	}

	var result checkOutput
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, output.String())
	}
	if result.ChangedFiles != 1 || len(result.AffectedRoutes) != 1 {
		t.Fatalf("unexpected check result: %#v", result)
	}
	if got := result.AffectedRoutes[0].Route.Path; got != "/users" {
		t.Fatalf("affected route path = %q, want /users", got)
	}
	if got := strings.Join(result.AffectedRoutes[0].Chain, " -> "); got != "getUser -> lookupUser" {
		t.Fatalf("impact chain = %q", got)
	}
}

func TestCheckReportsBreakingRequestContractDrift(t *testing.T) {
	root := createGitRepo(t)
	writeFile(t, root, "server.ts", `interface CreateUserRequest {
  id: string;
}
function createUser(input: CreateUserRequest) {}
app.post("/users", createUser);
`)
	git(t, root, "add", "server.ts")
	git(t, root, "-c", "user.name=AStra Test", "-c", "user.email=astra@example.invalid", "commit", "-m", "baseline")
	writeFile(t, root, "server.ts", `interface CreateUserRequest {
  id: string;
  email: string;
}
function createUser(input: CreateUserRequest) {}
app.post("/users", createUser);
`)

	var output bytes.Buffer
	if err := runAt([]string{"check", "--json"}, &output, &bytes.Buffer{}, root); err != nil {
		t.Fatal(err)
	}
	var result checkOutput
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, output.String())
	}
	if len(result.AffectedRoutes) != 1 || result.AffectedRoutes[0].Severity != "breaking" ||
		!strings.Contains(result.AffectedRoutes[0].Reason, `required request field "email" was added`) {
		t.Fatalf("CLI did not report request contract drift: %#v", result.AffectedRoutes)
	}
}

func TestCheckGateHonorsIgnoredPathsAndFailOn(t *testing.T) {
	root := createGitRepo(t)
	writeFile(t, root, "src/users.ts", `function getUser(req, res) {
  lookupUser();
}
function lookupUser() {
  return 1;
}
app.get("/users", getUser);
`)
	writeFile(t, root, "docs/api.md", "Baseline API documentation\n")
	git(t, root, "add", ".")
	git(t, root, "-c", "user.name=AStra Test", "-c", "user.email=astra@example.invalid", "commit", "-m", "baseline")
	writeFile(t, root, "src/users.ts", `function getUser(req, res) {
  lookupUser();
}
function lookupUser() {
  return 2;
}
app.get("/users", getUser);
`)
	writeFile(t, root, "docs/api.md", "Updated API documentation\n")
	writeFile(t, root, ".astrarc.json", `{"ignored_paths":["docs/**"],"fail_on":["potential"]}`)

	var output bytes.Buffer
	err := runAt([]string{"check", "--json", "--gate"}, &output, &bytes.Buffer{}, root)
	if err == nil {
		t.Fatal("expected gate to fail on potential route impact")
	}
	var result map[string]any
	if decodeErr := json.Unmarshal(output.Bytes(), &result); decodeErr != nil {
		t.Fatalf("invalid gate JSON: %v\n%s", decodeErr, output.String())
	}
	if result["status"] != "fail" || result["changed_files"] != float64(1) {
		t.Fatalf("gate did not apply policy/ignore docs: %#v", result)
	}
}

func TestCheckRejectsBaseOptionInjection(t *testing.T) {
	root := createGitRepo(t)
	for _, base := range []string{"--output=report", "bad\nref"} {
		if err := runAt([]string{"check", "--base", base}, &bytes.Buffer{}, &bytes.Buffer{}, root); err == nil {
			t.Errorf("check accepted invalid base %q", base)
		}
	}
}

func TestInstallHookDoesNotOverwriteExistingHook(t *testing.T) {
	root := createGitRepo(t)
	var output bytes.Buffer
	if err := runAt([]string{"install-hook"}, &output, &bytes.Buffer{}, root); err != nil {
		t.Fatal(err)
	}
	hookPath := filepath.Join(root, ".git", "hooks", "pre-commit")
	content, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "#!/bin/sh\nexec astra check --staged\n" {
		t.Fatalf("unexpected hook content: %q", content)
	}
	if err := runAt([]string{"install-hook"}, &bytes.Buffer{}, &bytes.Buffer{}, root); err == nil {
		t.Fatal("expected refusing to overwrite the installed hook")
	}
}

func TestBenchCommandRunsEmbeddedCorpus(t *testing.T) {
	var output bytes.Buffer
	if err := runAt([]string{"bench"}, &output, &bytes.Buffer{}, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"Precision: 50.0%",
		"Recall: 66.7%",
		"False-positive rate: 40.0%",
		"~ heuristic finding",
		"⚠ dynamic/unresolved uncertainty",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("benchmark output missing %q:\n%s", expected, output.String())
		}
	}
}

func TestMCPCommandStartsStdioProtocolServer(t *testing.T) {
	root := createGitRepo(t)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.WriteString(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}` + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	previousStdin := os.Stdin
	os.Stdin = reader
	defer func() {
		os.Stdin = previousStdin
		reader.Close()
	}()

	var output bytes.Buffer
	if err := runAt([]string{"mcp"}, &output, &bytes.Buffer{}, root); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"protocolVersion":"2025-06-18"`) {
		t.Fatalf("mcp command did not serve initialize response: %s", output.String())
	}
}

func createGitRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	git(t, root, "init", "-q")
	return root
}

func writeFile(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func git(t *testing.T, root string, args ...string) {
	t.Helper()
	commandArgs := append([]string{"-C", root}, args...)
	command := exec.Command("git", commandArgs...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
	}
}
