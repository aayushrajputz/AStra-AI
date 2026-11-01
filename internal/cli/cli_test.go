package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/astra-ai/astra/internal/analyzer"
	"github.com/astra-ai/astra/internal/policy"
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

func TestMergeGateBlocksThenPassesAfterRemainingCallerIsFixed(t *testing.T) {
	root := createGitRepo(t)
	writeFile(t, root, ".astrarc.json", `{"fail_on":"unresolved-breaking","allow_heuristic_failures":true}`)
	baseline := `function transfer(id: string) {}
function handler(req, res) {
  transfer(req.params.id);
}
app.post("/transfer", handler);
`
	writeFile(t, root, "server.ts", baseline)
	git(t, root, "add", ".")
	git(t, root, "-c", "user.name=AStra Test", "-c", "user.email=astra@example.invalid", "commit", "-m", "baseline")

	broken := strings.Replace(baseline, "function transfer(id: string)", "function transfer(id: string, currency: string)", 1)
	writeFile(t, root, "server.ts", broken)
	var output bytes.Buffer
	err := runAt([]string{"check", "--gate", "--json"}, &output, &bytes.Buffer{}, root)
	if !errors.Is(err, ErrGateFailed) {
		t.Fatalf("stale caller should block the gate; err = %v, output = %s", err, output.String())
	}
	var blocked checkOutput
	if decodeErr := json.Unmarshal(output.Bytes(), &blocked); decodeErr != nil {
		t.Fatalf("invalid blocked-gate JSON: %v\n%s", decodeErr, output.String())
	}
	if blocked.Status != "fail" || len(blocked.AffectedRoutes) != 1 ||
		blocked.AffectedRoutes[0].Resolution != "unresolved" ||
		len(blocked.AffectedRoutes[0].CallSites) != 1 {
		t.Fatalf("stale caller was not reported as unresolved: %#v", blocked)
	}

	fixed := strings.Replace(broken, "transfer(req.params.id);", `transfer(req.params.id, "INR");`, 1)
	writeFile(t, root, "server.ts", fixed)
	output.Reset()
	if err := runAt([]string{"check", "--gate", "--json"}, &output, &bytes.Buffer{}, root); err != nil {
		t.Fatalf("updated caller should pass the gate: %v\n%s", err, output.String())
	}
	var passed checkOutput
	if decodeErr := json.Unmarshal(output.Bytes(), &passed); decodeErr != nil {
		t.Fatalf("invalid passing-gate JSON: %v\n%s", decodeErr, output.String())
	}
	if passed.Status != "pass" || len(passed.AffectedRoutes) != 1 ||
		passed.AffectedRoutes[0].Resolution != "resolved" {
		t.Fatalf("updated caller did not resolve the finding: %#v", passed)
	}
}

func TestCheckStagedUsesIndexContentForPartiallyStagedFile(t *testing.T) {
	root := createGitRepo(t)
	writeFile(t, root, "server.ts", `function getUser(req, res) {
  lookupUser();
}
function lookupUser() {
  return 1;
}
app.get("/users", getUser);
`)
	git(t, root, "add", "server.ts")
	git(t, root, "-c", "user.name=AStra Test", "-c", "user.email=astra@example.invalid", "commit", "-m", "baseline")

	writeFile(t, root, "server.ts", `function getUser(req, res) {
  lookupUser();
}
function lookupUser() {
  return 2;
}
app.get("/users", getUser);
`)
	git(t, root, "add", "server.ts")
	writeFile(t, root, "server.ts", `function getUser(req, res) {
  lookupUser();
}
function lookupUser() {
  return 2;
}
app.get("/working-tree-only", getUser);
`)

	var output bytes.Buffer
	if err := runAt([]string{"check", "--staged", "--json"}, &output, &bytes.Buffer{}, root); err != nil {
		t.Fatal(err)
	}
	var result checkOutput
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("invalid staged check JSON: %v\n%s", err, output.String())
	}
	if result.ChangedFiles != 1 || len(result.Routes) != 1 || result.Routes[0].Path != "/users" {
		t.Fatalf("staged analysis used working-tree content: %#v", result)
	}
}

func TestStagedGateSkipsRepositoryAnalysisWhenIndexIsClean(t *testing.T) {
	root := createGitRepo(t)
	writeFile(t, root, "server.ts", `app.get("/status", statusHandler);
function statusHandler(req, res) {}
`)
	git(t, root, "add", "server.ts")
	git(t, root, "-c", "user.name=AStra Test", "-c", "user.email=astra@example.invalid", "commit", "-m", "baseline")
	var output bytes.Buffer
	if err := runAt([]string{"check", "--staged", "--gate", "--json"}, &output, &bytes.Buffer{}, root); err != nil {
		t.Fatal(err)
	}
	var result checkOutput
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("invalid clean-index gate JSON: %v\n%s", err, output.String())
	}
	if result.Status != "pass" || result.ChangedFiles != 0 || len(result.Routes) != 0 {
		t.Fatalf("clean staged gate should not analyze unchanged repository routes: %#v", result)
	}
}

func TestExitCodeSeparatesGateFailureFromToolError(t *testing.T) {
	if got := ExitCode(ErrGateFailed); got != 1 {
		t.Fatalf("gate failure exit code = %d, want 1", got)
	}
	if got := ExitCode(errors.New("analysis failed")); got != 2 {
		t.Fatalf("tool failure exit code = %d, want 2", got)
	}
	if got := ExitCode(nil); got != 0 {
		t.Fatalf("success exit code = %d, want 0", got)
	}
}

func TestPrintCheckIncludesActiveWaiversWithoutViolations(t *testing.T) {
	var output bytes.Buffer
	err := printCheck(&output, checkOutput{
		Status: "pass",
		ActiveWaivers: []policy.Waiver{{
			Symbol: "TransferService.Move", Reason: "migration window",
			Owner: "payments", Expires: "2099-12-31",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "active waiver: TransferService.Move") {
		t.Fatalf("active waiver missing from text report: %s", output.String())
	}
}

func TestPrintCheckNeverSaysNoAffectedWhenChangeIsUntraced(t *testing.T) {
	var output bytes.Buffer
	err := printCheck(&output, checkOutput{
		ChangedFiles: 1,
		Warnings: []analyzer.Warning{{
			File: "src/validators/auth.validator.ts", Line: 8, Message: "change could not be traced",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if !strings.Contains(text, "1 change(s) could not be traced") ||
		!strings.Contains(text, "src/validators/auth.validator.ts:8") ||
		strings.Contains(text, "No affected routes detected.") {
		t.Fatalf("untraced change was silently presented as clean:\n%s", text)
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

func TestCheckAIIsOptIn(t *testing.T) {
	root := createGitRepo(t)
	writeFile(t, root, "server.ts", `function getUser(req, res) {}
app.get("/users", getUser);
`)
	git(t, root, "add", "server.ts")
	git(t, root, "-c", "user.name=AStra Test", "-c", "user.email=astra@example.invalid", "commit", "-m", "baseline")
	writeFile(t, root, "server.ts", `function getUser(req, res) {
  lookupUser();
}
function lookupUser() {}
app.get("/users", getUser);
`)

	var output bytes.Buffer
	if err := runAt([]string{"check", "--json"}, &output, &bytes.Buffer{}, root); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "ai_explanation") {
		t.Fatalf("default check unexpectedly included AI output: %s", output.String())
	}
}

func TestCheckRejectsUnknownAIProvider(t *testing.T) {
	root := createChangedRouteRepo(t)
	err := runAt([]string{
		"check", "--ai-provider", "unknown", "--ai-model", "test-model",
	}, &bytes.Buffer{}, &bytes.Buffer{}, root)
	if err == nil || !strings.Contains(err.Error(), "unsupported AI provider") {
		t.Fatalf("expected unsupported provider error, got %v", err)
	}
}

func TestCheckAIDryRunPrintsRedactedPreviewWithoutNetwork(t *testing.T) {
	t.Setenv("ASTRA_CACHE_DIR", filepath.Join(t.TempDir(), "cache"))
	t.Setenv("OPENAI_API_KEY", "dry-run-secret")
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()
	root := createChangedRouteRepo(t)
	var output bytes.Buffer
	err := runAt([]string{
		"check", "--ai-provider", "openai-compatible", "--ai-model", "test-model",
		"--ai-endpoint", server.URL, "--ai-dry-run",
	}, &output, &bytes.Buffer{}, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"AI dry-run preview", "Authorization", "lookupUser"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("dry-run output missing %q:\n%s", expected, output.String())
		}
	}
	if strings.Contains(output.String(), "dry-run-secret") {
		t.Fatal("dry-run preview exposed the provider API key")
	}
	if calls.Load() != 0 {
		t.Fatalf("dry-run made %d network calls", calls.Load())
	}
}

func TestCheckAIUsesEnvironmentKeyAndDoesNotChangeGateResultOnFailure(t *testing.T) {
	t.Setenv("ASTRA_CACHE_DIR", filepath.Join(t.TempDir(), "cache"))
	t.Setenv("OPENAI_API_KEY", "test-secret")
	var gotAuthorization atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		gotAuthorization.Store(request.Header.Get("Authorization"))
		http.Error(writer, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	root := createChangedRouteRepo(t)
	writeFile(t, root, ".astrarc.json", `{"fail_on":["potential"]}`)

	var output bytes.Buffer
	err := runAt([]string{
		"check", "--json", "--gate", "--ai-provider", "openai-compatible",
		"--ai-model", "test-model", "--ai-endpoint", server.URL,
	}, &output, &bytes.Buffer{}, root)
	if err == nil || !strings.Contains(err.Error(), "AI") {
		t.Fatalf("expected surfaced AI failure, got %v", err)
	}
	if got := gotAuthorization.Load(); got != "Bearer test-secret" {
		t.Fatalf("provider environment key was not used: %#v", got)
	}
	var result map[string]any
	if decodeErr := json.Unmarshal(output.Bytes(), &result); decodeErr != nil {
		t.Fatalf("invalid deterministic report: %v\n%s", decodeErr, output.String())
	}
	if result["status"] != "fail" {
		t.Fatalf("AI failure changed deterministic gate result: %#v", result)
	}
}

func TestCheckAnthropicAIExplanationUsesProviderEnvironmentKey(t *testing.T) {
	t.Setenv("ASTRA_CACHE_DIR", filepath.Join(t.TempDir(), "cache"))
	t.Setenv("ANTHROPIC_API_KEY", "anthropic-test-secret")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("x-api-key"); got != "anthropic-test-secret" {
			t.Errorf("Anthropic API key header = %q", got)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"content":[{"type":"text","text":"{\"summary\":\"One deterministic route is affected.\",\"routes\":[{\"method\":\"GET\",\"path\":\"/users\",\"explanation\":\"The changed helper is in the route chain.\"}]}"}]}`))
	}))
	defer server.Close()
	root := createChangedRouteRepo(t)
	var output bytes.Buffer
	if err := runAt([]string{
		"check", "--json", "--ai-provider", "anthropic", "--ai-model", "test-model",
		"--ai-endpoint", server.URL,
	}, &output, &bytes.Buffer{}, root); err != nil {
		t.Fatal(err)
	}
	var result checkOutput
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("invalid check output: %v\n%s", err, output.String())
	}
	if result.AIExplanation == nil || result.AIExplanation.Summary != "One deterministic route is affected." {
		t.Fatalf("AI explanation missing from output: %#v", result)
	}
	if len(result.AffectedRoutes) != 1 || result.AffectedRoutes[0].Route.Path != "/users" {
		t.Fatalf("AI response changed deterministic findings: %#v", result.AffectedRoutes)
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
	if !strings.Contains(string(content), "astra check --staged --gate") ||
		!strings.Contains(string(content), "--no-verify bypasses this hook") ||
		!strings.Contains(string(content), "CI remains the authoritative merge gate") {
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
		"Precision: 75.0%",
		"Recall: 75.0%",
		"False-positive rate: 16.7%",
		"go-gin-required-parameter",
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

func createChangedRouteRepo(t *testing.T) string {
	t.Helper()
	root := createGitRepo(t)
	writeFile(t, root, "server.ts", `function getUser(req, res) {
  lookupUser();
}
function lookupUser() {
  return 1;
}
app.get("/users", getUser);
`)
	git(t, root, "add", "server.ts")
	git(t, root, "-c", "user.name=AStra Test", "-c", "user.email=astra@example.invalid", "commit", "-m", "baseline")
	writeFile(t, root, "server.ts", `function getUser(req, res) {
  lookupUser();
}
function lookupUser() {
  return 2;
}
app.get("/users", getUser);
`)
	return root
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
