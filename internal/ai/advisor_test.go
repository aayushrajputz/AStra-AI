package ai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/astra-ai/astra/internal/analyzer"
	"github.com/astra-ai/astra/internal/diff"
)

func TestBuildRequestContainsOnlySignatureAndRouteMetadata(t *testing.T) {
	changes := []diff.File{{
		Path: "handler.go",
		Changes: []diff.Change{
			{Kind: diff.DeletedChange, Text: `func handle(req *http.Request) { panic("PRIVATE_OLD_BODY") }`},
			{Kind: diff.AddedChange, Text: `func handle(req *http.Request, id string) { panic("PRIVATE_NEW_BODY") }`},
			{Kind: diff.AddedChange, Text: `fmt.Println("PRIVATE_NON_SIGNATURE_BODY")`},
		},
	}}
	impacts := []analyzer.RouteImpact{{
		Route: analyzer.Route{Method: "GET", Path: "/users/:id", Handlers: []string{"handle"}},
		Chain: []string{"handle", "loadUser"}, Severity: "breaking",
		Reason: "required parameter added", Confidence: "heuristic",
	}}
	input := BuildInput(changes, impacts)
	if len(input.Signatures) != 2 || len(input.Routes) != 1 {
		t.Fatalf("unexpected advisor input: %#v", input)
	}
	request, err := BuildRequest("openai-compatible", "test-model", input)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, privateBody := range []string{"PRIVATE_OLD_BODY", "PRIVATE_NEW_BODY", "PRIVATE_NON_SIGNATURE_BODY"} {
		if strings.Contains(text, privateBody) {
			t.Fatalf("request leaked source body %q: %s", privateBody, text)
		}
	}
	if !strings.Contains(text, "handle(req *http.Request, id string)") {
		t.Fatalf("request omitted normalized signature: %s", text)
	}
}

func TestBuildRequestUsesProviderSpecificSchemas(t *testing.T) {
	input := Input{Routes: []RouteInput{{Method: "GET", Path: "/health", Severity: "potential"}}}
	openAI, err := BuildRequest("openai-compatible", "model-a", input)
	if err != nil {
		t.Fatal(err)
	}
	if openAI.URL != "https://api.openai.com/v1/chat/completions" ||
		openAI.Headers.Get("Authorization") != "Bearer <redacted>" {
		t.Fatalf("unexpected OpenAI-compatible preview: %#v", openAI)
	}
	if _, ok := openAI.Body.(OpenAIRequest); !ok {
		t.Fatalf("unexpected OpenAI request body %T", openAI.Body)
	}
	anthropic, err := BuildRequest("anthropic", "model-b", input)
	if err != nil {
		t.Fatal(err)
	}
	if anthropic.URL != "https://api.anthropic.com/v1/messages" ||
		anthropic.Headers.Get("anthropic-version") == "" ||
		anthropic.Headers.Get("x-api-key") != "<redacted>" {
		t.Fatalf("unexpected Anthropic preview: %#v", anthropic)
	}
	if _, ok := anthropic.Body.(AnthropicRequest); !ok {
		t.Fatalf("unexpected Anthropic request body %T", anthropic.Body)
	}
}

func TestParseExplanationRequiresStrictSchema(t *testing.T) {
	valid := `{"summary":"One route may be affected.","routes":[{"method":"GET","path":"/users","explanation":"The handler calls the changed function."}]}`
	if _, err := ParseExplanation([]byte(valid)); err != nil {
		t.Fatalf("valid structured explanation rejected: %v", err)
	}
	for _, invalid := range []string{
		`{"summary":"x","routes":[],"extra":"not allowed"}`,
		`{"summary":"x","routes":[{"method":"GET","path":"/","explanation":"x","extra":true}]}`,
		`{"summary":"x","routes":[{"method":"GET","path":"/","explanation":"x"}]} trailing`,
		`{"summary":"","routes":[]}`,
	} {
		if _, err := ParseExplanation([]byte(invalid)); err == nil {
			t.Errorf("invalid model response was accepted: %s", invalid)
		}
	}
}

func TestAdvisorCacheHitMakesNoNetworkCall(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"choices":[{"message":{"content":"{\"summary\":\"No deterministic impact changed.\",\"routes\":[]}"}}]}`))
	}))
	defer server.Close()

	cacheDir := t.TempDir()
	config := Config{
		Provider: "openai-compatible", Model: "test-model", APIKey: "test-key",
		Endpoint: server.URL, CacheDir: cacheDir, HTTPClient: server.Client(),
	}
	input := Input{Routes: []RouteInput{{Method: "GET", Path: "/users", Severity: "breaking"}}}
	first, err := Explain(context.Background(), config, input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Explain(context.Background(), config, input)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("cache hit called network again: %d requests", calls.Load())
	}
	if first.Summary != second.Summary {
		t.Fatalf("cache result differs: %#v vs %#v", first, second)
	}
}

func TestAnthropicResponseMustBeStrictJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"content":[{"type":"text","text":"Here is a summary: {\"summary\":\"x\",\"routes\":[]}"}]}`))
	}))
	defer server.Close()
	_, err := Explain(context.Background(), Config{
		Provider: "anthropic", Model: "test-model", APIKey: "test-key",
		Endpoint: server.URL, CacheDir: filepath.Join(t.TempDir(), "cache"), HTTPClient: server.Client(),
	}, Input{})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "json") {
		t.Fatalf("expected strict JSON response failure, got %v", err)
	}
}

func TestAdvisorRejectsRoutesOutsideDeterministicInput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"choices":[{"message":{"content":"{\"summary\":\"Invented route\",\"routes\":[{\"method\":\"GET\",\"path\":\"/admin\",\"explanation\":\"Not in input.\"}]}"}}]}`))
	}))
	defer server.Close()
	_, err := Explain(context.Background(), Config{
		Provider: OpenAICompatible, Model: "test-model", APIKey: "test-key",
		Endpoint: server.URL, CacheDir: filepath.Join(t.TempDir(), "cache"), HTTPClient: server.Client(),
	}, Input{Routes: []RouteInput{{Method: "GET", Path: "/users", Severity: "breaking"}}})
	if err == nil || !strings.Contains(err.Error(), "not present in deterministic findings") {
		t.Fatalf("expected invented route to be rejected, got %v", err)
	}
}

func TestCacheKeyIncludesProviderModelAndInput(t *testing.T) {
	input := Input{Routes: []RouteInput{{Method: "GET", Path: "/users", Severity: "breaking"}}}
	request, err := BuildRequest("openai-compatible", "model-a", input)
	if err != nil {
		t.Fatal(err)
	}
	key, err := cacheKey(request)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := json.Marshal(struct {
		Provider string `json:"provider"`
		URL      string `json:"url"`
		Body     []byte `json:"body"`
	}{Provider: request.Provider, URL: request.URL, Body: request.BodyBytes})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(identity)
	if key != hex.EncodeToString(digest[:]) {
		t.Fatalf("cache key does not hash exact request body: %s", key)
	}
	if _, err := os.Stat(filepath.Join(t.TempDir(), key)); !os.IsNotExist(err) {
		t.Fatalf("unexpected cache fixture state: %v", err)
	}
}
