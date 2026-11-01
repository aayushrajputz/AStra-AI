package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/astra-ai/astra/internal/analyzer"
	"github.com/astra-ai/astra/internal/diff"
)

func TestProtocolInitializeListsToolsAndPings(t *testing.T) {
	root := createRepo(t)
	server, err := NewServer(root)
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"ping"}`,
	}, "\n") + "\n"
	var output bytes.Buffer
	if err := server.Serve(strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}

	responses := decodeResponses(t, &output)
	if len(responses) != 3 {
		t.Fatalf("got %d responses, want 3 (initialized notification has no response)", len(responses))
	}
	initialize := responses[0]["result"].(map[string]any)
	if initialize["protocolVersion"] != "2025-06-18" {
		t.Fatalf("unexpected negotiated protocol: %#v", initialize)
	}
	capabilities := initialize["capabilities"].(map[string]any)
	if capabilities["tools"] == nil || capabilities["resources"] == nil {
		t.Fatalf("missing MCP capabilities: %#v", capabilities)
	}
	toolsResult := responses[1]["result"].(map[string]any)
	tools := toolsResult["tools"].([]any)
	if len(tools) != 5 {
		t.Fatalf("got %d tools, want 5", len(tools))
	}
	names := make(map[string]bool)
	for _, rawTool := range tools {
		tool := rawTool.(map[string]any)
		names[tool["name"].(string)] = tool["inputSchema"] != nil
	}
	for _, name := range []string{
		"astra_check_diff", "astra_blast_radius", "astra_list_routes",
		"astra_explain_route", "astra_gate",
	} {
		if !names[name] {
			t.Errorf("tool %q missing or has no input schema", name)
		}
	}
	for _, rawTool := range tools {
		tool := rawTool.(map[string]any)
		if tool["annotations"].(map[string]any)["readOnlyHint"] != true {
			t.Errorf("tool %s is not declared read-only", tool["name"])
		}
		schema := tool["inputSchema"].(map[string]any)
		if required, ok := schema["required"].([]any); !ok {
			t.Errorf("tool %s has invalid required schema field: %#v", tool["name"], schema["required"])
		} else if len(required) == 0 && tool["name"] != "astra_list_routes" && tool["name"] != "astra_gate" {
			t.Errorf("tool %s unexpectedly has no required arguments", tool["name"])
		}
	}
	if responses[2]["error"] != nil {
		t.Fatalf("ping returned error: %#v", responses[2])
	}
}

func TestToolsListRoutesAndCheckDiffMatchRepositoryAnalysis(t *testing.T) {
	root := createRepo(t)
	write(t, root, "src/routes.ts", `function getUser(req, res) {
  lookupUser();
}
function lookupUser() {
  return 1;
}
app.get("/users", getUser);
`)
	git(t, root, "add", ".")
	git(t, root, "-c", "user.name=AStra Test", "-c", "user.email=astra@example.invalid", "commit", "-m", "baseline")
	write(t, root, "src/routes.ts", `function getUser(req, res) {
  lookupUser();
}
function lookupUser() {
  return 2;
}
app.get("/users", getUser);
`)

	server, err := NewServer(root)
	if err != nil {
		t.Fatal(err)
	}
	requests := []map[string]any{
		{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
			"params": map[string]any{"name": "astra_list_routes", "arguments": map[string]any{}}},
		{"jsonrpc": "2.0", "id": 2, "method": "tools/call",
			"params": map[string]any{"name": "astra_check_diff", "arguments": map[string]any{"mode": "working"}}},
	}
	var input strings.Builder
	for _, request := range requests {
		encoded, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		input.Write(encoded)
		input.WriteByte('\n')
	}
	var output bytes.Buffer
	if err := server.Serve(strings.NewReader(input.String()), &output); err != nil {
		t.Fatal(err)
	}
	responses := decodeResponses(t, &output)

	list := toolText(t, responses[0])
	if !strings.Contains(list, `"path":"/users"`) || !strings.Contains(list, `"method":"GET"`) {
		t.Fatalf("list_routes missing route details: %s", list)
	}
	check := toolText(t, responses[1])
	if !strings.Contains(check, `"path":"/users"`) ||
		!strings.Contains(check, `"chain":[`) ||
		!strings.Contains(check, `"severity":"potential"`) {
		t.Fatalf("check_diff missing impacted route report: %s", check)
	}

	var gotList analyzer.Report
	if err := json.Unmarshal([]byte(list), &gotList); err != nil {
		t.Fatal(err)
	}
	wantList, err := analyzer.Analyze(root)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotList.Routes, wantList.Routes) {
		t.Fatalf("MCP list_routes differs from direct analyzer result:\ngot: %#v\nwant: %#v", gotList.Routes, wantList.Routes)
	}
	var gotCheck checkReport
	if err := json.Unmarshal([]byte(check), &gotCheck); err != nil {
		t.Fatal(err)
	}
	diffText := gitOutputTest(t, root, "diff", "--no-ext-diff", "--unified=0", "HEAD")
	changes, err := diff.Parse(strings.NewReader(diffText))
	if err != nil {
		t.Fatal(err)
	}
	wantAnalysis, err := analyzer.AnalyzeDiff(root, changes)
	if err != nil {
		t.Fatal(err)
	}
	wantCheck := checkReport{
		ChangedFiles: len(changes), HasChanges: len(changes) > 0,
		Routes: wantAnalysis.Routes, AffectedRoutes: wantAnalysis.AffectedRoutes,
		Warnings: wantAnalysis.Warnings,
	}
	wantCheckJSON, err := json.Marshal(wantCheck)
	if err != nil {
		t.Fatal(err)
	}
	var normalizedWantCheck checkReport
	if err := json.Unmarshal(wantCheckJSON, &normalizedWantCheck); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotCheck, normalizedWantCheck) {
		t.Fatalf("MCP check_diff differs from direct analyzer/CLI JSON result:\ngot: %#v\nwant: %#v", gotCheck, wantCheck)
	}
}

func TestCheckDiffReportsBreakingRequestContractDrift(t *testing.T) {
	root := createRepo(t)
	write(t, root, "src/routes.ts", `interface CreateUserRequest {
  id: string;
}
function createUser(input: CreateUserRequest) {}
app.post("/users", createUser);
`)
	git(t, root, "add", ".")
	git(t, root, "-c", "user.name=AStra Test", "-c", "user.email=astra@example.invalid", "commit", "-m", "baseline")
	write(t, root, "src/routes.ts", `interface CreateUserRequest {
  id: string;
  email: string;
}
function createUser(input: CreateUserRequest) {}
app.post("/users", createUser);
`)
	server, err := NewServer(root)
	if err != nil {
		t.Fatal(err)
	}
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"astra_check_diff","arguments":{"mode":"working"}}}` + "\n"
	var output bytes.Buffer
	if err := server.Serve(strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	result := toolText(t, decodeResponses(t, &output)[0])
	if !strings.Contains(result, `"severity":"breaking"`) ||
		!strings.Contains(result, `required request field \"email\" was added`) {
		t.Fatalf("MCP check_diff did not report contract drift: %s", result)
	}
}

func TestInvalidMethodsToolsAndOutOfRootPathsReturnJSONRPCErrors(t *testing.T) {
	root := createRepo(t)
	server, err := NewServer(root)
	if err != nil {
		t.Fatal(err)
	}
	requests := []string{
		`{"jsonrpc":"2.0","id":1,"method":"unknown/method"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"not_a_tool","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"astra_blast_radius","arguments":{"file":"../outside.ts","symbol":"secret"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"astra_blast_radius","arguments":{"file":"src/routes.ts"}}}`,
	}
	var output bytes.Buffer
	if err := server.Serve(strings.NewReader(strings.Join(requests, "\n")+"\n"), &output); err != nil {
		t.Fatal(err)
	}
	responses := decodeResponses(t, &output)
	if len(responses) != len(requests) {
		t.Fatalf("got %d responses, want %d", len(responses), len(requests))
	}
	wantCodes := []float64{-32601, -32602, -32602, -32602}
	for i, response := range responses {
		errorObject, ok := response["error"].(map[string]any)
		if !ok || errorObject["code"] != wantCodes[i] {
			t.Errorf("response %d error = %#v, want code %v", i, response["error"], wantCodes[i])
		}
	}
}

func TestExplainRouteAndGateAndLatestReportResource(t *testing.T) {
	root := createRepo(t)
	write(t, root, "src/routes.ts", `function getUser(req, res) {
  lookupUser();
}
function lookupUser() {
  return 1;
}
app.get("/users", getUser);
`)
	git(t, root, "add", ".")
	git(t, root, "-c", "user.name=AStra Test", "-c", "user.email=astra@example.invalid", "commit", "-m", "baseline")
	write(t, root, "src/routes.ts", `function getUser(req, res) {
  lookupUser();
}
function lookupUser() {
  return 2;
}
app.get("/users", getUser);
`)

	server, err := NewServer(root)
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"astra_explain_route","arguments":{"method":"GET","path":"/users"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"astra_gate","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"astra://report/latest"}}`,
	}, "\n") + "\n"
	var output bytes.Buffer
	if err := server.Serve(strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	responses := decodeResponses(t, &output)
	if !strings.Contains(toolText(t, responses[0]), "getUser") ||
		!strings.Contains(toolText(t, responses[0]), "lookupUser") {
		t.Fatalf("explain_route missing call chain: %s", toolText(t, responses[0]))
	}
	if !strings.Contains(toolText(t, responses[1]), `"status":"pass"`) {
		t.Fatalf("default gate did not pass: %s", toolText(t, responses[1]))
	}
	readResult := responses[2]["result"].(map[string]any)
	contents := readResult["contents"].([]any)
	if len(contents) != 1 || contents[0].(map[string]any)["uri"] != "astra://report/latest" {
		t.Fatalf("unexpected report resource response: %#v", readResult)
	}
}

func TestBlastRadiusBySymbolAndLine(t *testing.T) {
	root := createRepo(t)
	write(t, root, "src/routes.ts", `function loadUser() {
  return 1;
}
function getUser(req, res) {
  loadUser();
}
app.get("/users", getUser);
`)
	server, err := NewServer(root)
	if err != nil {
		t.Fatal(err)
	}
	requests := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"astra_blast_radius","arguments":{"file":"src/routes.ts","symbol":"loadUser"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"astra_blast_radius","arguments":{"file":"src/routes.ts","line":1}}}`,
	}
	var output bytes.Buffer
	if err := server.Serve(strings.NewReader(strings.Join(requests, "\n")+"\n"), &output); err != nil {
		t.Fatal(err)
	}
	responses := decodeResponses(t, &output)
	for _, response := range responses {
		if !strings.Contains(toolText(t, response), `"path":"/users"`) {
			t.Errorf("blast radius did not identify public route: %s", toolText(t, response))
		}
	}
}

func TestGateHonorsFailOnPolicy(t *testing.T) {
	root := createRepo(t)
	write(t, root, "src/routes.ts", `function getUser(req, res) {
  lookupUser();
}
function lookupUser() {
  return 1;
}
app.get("/users", getUser);
`)
	git(t, root, "add", ".")
	git(t, root, "-c", "user.name=AStra Test", "-c", "user.email=astra@example.invalid", "commit", "-m", "baseline")
	write(t, root, "src/routes.ts", `function getUser(req, res) {
  lookupUser();
}
function lookupUser() {
  return 2;
}
app.get("/users", getUser);
`)
	write(t, root, ".astrarc.json", `{"fail-on":"potential"}`)
	server, err := NewServer(root)
	if err != nil {
		t.Fatal(err)
	}
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"astra_gate","arguments":{}}}` + "\n"
	var output bytes.Buffer
	if err := server.Serve(strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	result := toolText(t, decodeResponses(t, &output)[0])
	if !strings.Contains(result, `"status":"fail"`) || !strings.Contains(result, `"violations":[`) {
		t.Fatalf("gate did not enforce potential fail-on policy: %s", result)
	}
}

func TestGateHonorsIgnoredPathsAndSeverityLabels(t *testing.T) {
	root := createRepo(t)
	write(t, root, "src/routes.ts", `function getUser(req, res) {
  lookupUser();
}
function lookupUser() {
  return 1;
}
app.get("/users", getUser);
`)
	git(t, root, "add", ".")
	git(t, root, "-c", "user.name=AStra Test", "-c", "user.email=astra@example.invalid", "commit", "-m", "baseline")
	write(t, root, "src/routes.ts", `function getUser(req, res) {
  lookupUser();
}
function lookupUser() {
  return 2;
}
app.get("/users", getUser);
`)
	write(t, root, ".astrarc.json", `{"ignored_paths":["src/**"],"severity_rules":{"potential":"warning"},"fail_on":["potential"]}`)
	server, err := NewServer(root)
	if err != nil {
		t.Fatal(err)
	}
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"astra_gate","arguments":{}}}` + "\n"
	var output bytes.Buffer
	if err := server.Serve(strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	result := toolText(t, decodeResponses(t, &output)[0])
	if !strings.Contains(result, `"status":"pass"`) ||
		!strings.Contains(result, `"changed_files":0`) {
		t.Fatalf("MCP gate did not apply ignored paths: %s", result)
	}
}

func TestGateAllowsExplicitEmptyFailOnPolicy(t *testing.T) {
	root := createRepo(t)
	write(t, root, "src/routes.ts", `function getUser(req, res) {
  lookupUser();
}
function lookupUser() {
  return 1;
}
app.get("/users", getUser);
`)
	git(t, root, "add", ".")
	git(t, root, "-c", "user.name=AStra Test", "-c", "user.email=astra@example.invalid", "commit", "-m", "baseline")
	write(t, root, "src/routes.ts", `function getUser(req, res) {
  lookupUser();
}
function lookupUser() {
  return 2;
}
app.get("/users", getUser);
`)
	write(t, root, ".astrarc.json", `{"fail-on":[]}`)
	server, err := NewServer(root)
	if err != nil {
		t.Fatal(err)
	}
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"astra_gate","arguments":{}}}` + "\n"
	var output bytes.Buffer
	if err := server.Serve(strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	result := toolText(t, decodeResponses(t, &output)[0])
	if !strings.Contains(result, `"status":"pass"`) {
		t.Fatalf("explicit empty fail-on policy should pass: %s", result)
	}
}

func TestMalformedJSONReturnsParseError(t *testing.T) {
	server, err := NewServer(createRepo(t))
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := server.Serve(strings.NewReader("{not-json}\n"), &output); err != nil {
		t.Fatal(err)
	}
	response := decodeResponses(t, &output)[0]
	errorObject := response["error"].(map[string]any)
	if errorObject["code"] != float64(-32700) {
		t.Fatalf("parse error code = %v", errorObject["code"])
	}
}

func TestInvalidRequestIDAndParamsReturnJSONRPCErrors(t *testing.T) {
	server, err := NewServer(createRepo(t))
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":true,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":"invalid"}`,
	}, "\n") + "\n"
	var output bytes.Buffer
	if err := server.Serve(strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	responses := decodeResponses(t, &output)
	wantCodes := []float64{-32600, -32602}
	for i, response := range responses {
		errorObject, ok := response["error"].(map[string]any)
		if !ok || errorObject["code"] != wantCodes[i] {
			t.Errorf("response %d error = %#v, want code %v", i, response["error"], wantCodes[i])
		}
	}
	if responses[0]["id"] != nil {
		t.Errorf("invalid request ID should be normalized to null, got %#v", responses[0]["id"])
	}
}

func TestOversizedRequestReturnsErrorAndServerContinues(t *testing.T) {
	server, err := NewServer(createRepo(t))
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Repeat("x", maxMessageBytes+1) + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"ping"}` + "\n"
	var output bytes.Buffer
	if err := server.Serve(strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	responses := decodeResponses(t, &output)
	if len(responses) != 2 {
		t.Fatalf("got %d responses, want oversized error and ping response", len(responses))
	}
	errorObject := responses[0]["error"].(map[string]any)
	if errorObject["code"] != float64(-32600) {
		t.Fatalf("oversized request error code = %v", errorObject["code"])
	}
	if responses[1]["result"] == nil {
		t.Fatalf("server did not continue after oversized request: %#v", responses[1])
	}
}

func TestResponseSizeLimitProducesJSONRPCError(t *testing.T) {
	server, err := NewServer(createRepo(t))
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	writer := bufio.NewWriter(&output)
	if err := server.writeResponse(writer, response{
		JSONRPC: "2.0", ID: json.RawMessage("1"),
		Result: strings.Repeat("x", maxOutputBytes),
	}); err != nil {
		t.Fatal(err)
	}
	response := decodeResponses(t, &output)[0]
	errorObject, ok := response["error"].(map[string]any)
	if !ok || errorObject["code"] != float64(-32603) {
		t.Fatalf("oversized response was not replaced by output-limit error: %#v", response)
	}
}

func decodeResponses(t *testing.T, output *bytes.Buffer) []map[string]any {
	t.Helper()
	responses := make([]map[string]any, 0)
	scanner := bufio.NewScanner(output)
	for scanner.Scan() {
		var response map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &response); err != nil {
			t.Fatalf("invalid JSON-RPC output %q: %v", scanner.Text(), err)
		}
		responses = append(responses, response)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return responses
}

func toolText(t *testing.T, response map[string]any) string {
	t.Helper()
	result, ok := response["result"].(map[string]any)
	if !ok {
		t.Fatalf("missing tool result: %#v", response)
	}
	content, ok := result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatalf("missing tool text content: %#v", result)
	}
	return content[0].(map[string]any)["text"].(string)
}

func createRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	git(t, root, "init", "-q")
	return root
}

func write(t *testing.T, root, relativePath, content string) {
	t.Helper()
	path := filepath.Join(root, relativePath)
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

func gitOutputTest(t *testing.T, root string, args ...string) string {
	t.Helper()
	commandArgs := append([]string{"-C", root}, args...)
	command := exec.Command("git", commandArgs...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return string(output)
}
