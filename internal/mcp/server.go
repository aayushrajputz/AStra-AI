package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/astra-ai/astra/internal/analyzer"
	"github.com/astra-ai/astra/internal/diff"
	"github.com/astra-ai/astra/internal/policy"
)

const (
	protocolVersion = "2025-11-25"
	maxMessageBytes = 1 << 20
	maxOutputBytes  = 1 << 20
)

type Server struct {
	root       string
	latestJSON json.RawMessage
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type toolDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema map[string]any  `json:"inputSchema"`
	Annotations map[string]bool `json:"annotations,omitempty"`
}

type toolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type toolResult struct {
	Content           []toolContent `json:"content"`
	StructuredContent any           `json:"structuredContent,omitempty"`
	IsError           bool          `json:"isError,omitempty"`
}

type checkReport struct {
	ChangedFiles   int                    `json:"changed_files"`
	HasChanges     bool                   `json:"has_changes"`
	Routes         []analyzer.Route       `json:"routes"`
	AffectedRoutes []analyzer.RouteImpact `json:"affected_routes"`
	Warnings       []analyzer.Warning     `json:"warnings,omitempty"`
}

type gateReport struct {
	Status     string      `json:"status"`
	Violations []string    `json:"violations"`
	Report     checkReport `json:"report"`
}

func NewServer(start string) (*Server, error) {
	root, err := gitOutput(start, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, fmt.Errorf("resolve repository root: %w", err)
	}
	root, err = filepath.Abs(strings.TrimSpace(root))
	if err != nil {
		return nil, fmt.Errorf("resolve repository root path: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("canonicalize repository root: %w", err)
	}
	return &Server{root: filepath.Clean(root)}, nil
}

func (server *Server) Serve(input io.Reader, output io.Writer) error {
	reader := bufio.NewReaderSize(input, 64*1024)
	writer := bufio.NewWriter(output)
	for {
		rawLine, tooLarge, readErr := readFrame(reader)
		if tooLarge {
			if err := server.writeResponse(writer, response{
				JSONRPC: "2.0", ID: json.RawMessage("null"),
				Error: &rpcError{Code: -32600, Message: "Request exceeds the 1 MiB input limit"},
			}); err != nil {
				return err
			}
		}
		line := bytes.TrimSpace(rawLine)
		if len(line) > 0 && !tooLarge {
			var req request
			if err := json.Unmarshal(line, &req); err != nil {
				if writeErr := server.writeResponse(writer, response{
					JSONRPC: "2.0", ID: json.RawMessage("null"),
					Error: &rpcError{Code: -32700, Message: "Parse error"},
				}); writeErr != nil {
					return writeErr
				}
			} else if req.JSONRPC != "2.0" || req.Method == "" ||
				(!isNotification(req.ID) && !validRequestID(req.ID)) {
				if !isNotification(req.ID) {
					id := requestID(req.ID)
					if !validRequestID(req.ID) {
						id = json.RawMessage("null")
					}
					if err := server.writeResponse(writer, response{
						JSONRPC: "2.0", ID: id,
						Error: &rpcError{Code: -32600, Message: "Invalid Request"},
					}); err != nil {
						return err
					}
				}
			} else if !validParams(req.Params) {
				if !isNotification(req.ID) {
					if err := server.writeResponse(writer, response{
						JSONRPC: "2.0", ID: requestID(req.ID),
						Error: &rpcError{Code: -32602, Message: "Invalid params"},
					}); err != nil {
						return err
					}
				}
			} else {
				result, rpcErr := server.dispatch(req.Method, req.Params)
				if !isNotification(req.ID) {
					res := response{JSONRPC: "2.0", ID: requestID(req.ID), Result: result}
					if rpcErr != nil {
						res.Result = nil
						res.Error = rpcErr
					}
					if err := server.writeResponse(writer, res); err != nil {
						return err
					}
				}
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("read MCP stdio request: %w", readErr)
		}
	}
	return writer.Flush()
}

func readFrame(reader *bufio.Reader) ([]byte, bool, error) {
	line := make([]byte, 0, 4096)
	tooLarge := false
	for {
		part, err := reader.ReadSlice('\n')
		if !tooLarge && len(line)+len(part) <= maxMessageBytes {
			line = append(line, part...)
		} else {
			tooLarge = true
			line = nil
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return line, tooLarge, err
		}
		return line, tooLarge, nil
	}
}

func (server *Server) writeResponse(writer *bufio.Writer, res response) error {
	encoded, err := json.Marshal(res)
	if err != nil {
		return fmt.Errorf("encode MCP response: %w", err)
	}
	if len(encoded) > maxOutputBytes {
		encoded, err = json.Marshal(response{
			JSONRPC: "2.0", ID: requestID(res.ID),
			Error: &rpcError{Code: -32603, Message: "Response exceeds the 1 MiB output limit"},
		})
		if err != nil {
			return fmt.Errorf("encode MCP output-limit error: %w", err)
		}
	}
	if _, err := writer.Write(encoded); err != nil {
		return fmt.Errorf("write MCP response: %w", err)
	}
	if err := writer.WriteByte('\n'); err != nil {
		return fmt.Errorf("write MCP response delimiter: %w", err)
	}
	return writer.Flush()
}

func (server *Server) dispatch(method string, rawParams json.RawMessage) (any, *rpcError) {
	switch method {
	case "initialize":
		return server.initialize(rawParams)
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": tools()}, nil
	case "tools/call":
		return server.callTool(rawParams)
	case "resources/list":
		return map[string]any{"resources": []map[string]any{{
			"uri": "astra://report/latest", "name": "Latest AStra analysis report",
			"description": "Most recent diff/gate report generated in this server session.",
			"mimeType":    "application/json",
		}}}, nil
	case "resources/read":
		return server.readResource(rawParams)
	default:
		return nil, &rpcError{Code: -32601, Message: "Method not found"}
	}
}

func (server *Server) initialize(params json.RawMessage) (any, *rpcError) {
	var values map[string]json.RawMessage
	if err := json.Unmarshal(params, &values); err != nil || values == nil {
		return nil, &rpcError{Code: -32602, Message: "Invalid initialize parameters"}
	}
	version := protocolVersion
	if rawVersion, ok := values["protocolVersion"]; ok {
		var requested string
		if err := json.Unmarshal(rawVersion, &requested); err != nil || requested == "" {
			return nil, &rpcError{Code: -32602, Message: "Invalid protocolVersion"}
		}
		switch requested {
		case protocolVersion, "2025-06-18", "2025-03-26", "2024-11-05":
			version = requested
		}
	}
	return map[string]any{
		"protocolVersion": version,
		"capabilities": map[string]any{
			"tools":     map[string]any{"listChanged": false},
			"resources": map[string]any{"subscribe": false, "listChanged": false},
		},
		"serverInfo":   map[string]any{"name": "astra", "version": "0.1.0"},
		"instructions": "Local read-only route impact analysis. Findings are heuristic where marked; dynamic code is explicitly warned.",
	}, nil
}

func tools() []toolDefinition {
	object := func(properties map[string]any, required ...string) map[string]any {
		return map[string]any{
			"type": "object", "properties": properties, "required": append([]string{}, required...),
			"additionalProperties": false,
		}
	}
	blastRadiusSchema := object(map[string]any{
		"file":   map[string]any{"type": "string"},
		"symbol": map[string]any{"type": "string"},
		"line":   map[string]any{"type": "integer", "minimum": 1},
	}, "file")
	blastRadiusSchema["oneOf"] = []map[string]any{
		{"required": []string{"symbol"}},
		{"required": []string{"line"}},
	}
	return []toolDefinition{
		{
			Name: "astra_check_diff", Description: "Analyze changed files and report potentially affected HTTP routes.",
			Annotations: map[string]bool{"readOnlyHint": true, "openWorldHint": false},
			InputSchema: object(map[string]any{
				"mode": map[string]any{"type": "string", "enum": []string{"staged", "working", "base"}},
				"base": map[string]any{"type": "string", "description": "Git base ref; required when mode is base."},
			}, "mode"),
		},
		{
			Name: "astra_blast_radius", Description: "Find publicly reachable routes for a symbol or source line before editing.",
			Annotations: map[string]bool{"readOnlyHint": true, "openWorldHint": false},
			InputSchema: blastRadiusSchema,
		},
		{
			Name: "astra_list_routes", Description: "List all detected HTTP routes and handler symbols.",
			Annotations: map[string]bool{"readOnlyHint": true, "openWorldHint": false},
			InputSchema: object(map[string]any{}),
		},
		{
			Name: "astra_explain_route", Description: "Show a route's downstream handler and dependency call chains.",
			Annotations: map[string]bool{"readOnlyHint": true, "openWorldHint": false},
			InputSchema: object(map[string]any{
				"method": map[string]any{"type": "string"},
				"path":   map[string]any{"type": "string"},
			}, "method", "path"),
		},
		{
			Name: "astra_gate", Description: "Evaluate the current diff using the repository .astrarc.json fail-on policy.",
			Annotations: map[string]bool{"readOnlyHint": true, "openWorldHint": false},
			InputSchema: object(map[string]any{}),
		},
	}
}

func (server *Server) callTool(params json.RawMessage) (any, *rpcError) {
	var request struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &request); err != nil || request.Name == "" {
		return nil, &rpcError{Code: -32602, Message: "Invalid tools/call parameters"}
	}
	arguments := make(map[string]json.RawMessage)
	if len(request.Arguments) > 0 && string(request.Arguments) != "null" {
		if err := json.Unmarshal(request.Arguments, &arguments); err != nil || arguments == nil {
			return nil, &rpcError{Code: -32602, Message: "Tool arguments must be a JSON object"}
		}
	}
	allowed := map[string]map[string]bool{
		"astra_check_diff":    {"mode": true, "base": true},
		"astra_blast_radius":  {"file": true, "symbol": true, "line": true},
		"astra_list_routes":   {},
		"astra_explain_route": {"method": true, "path": true},
		"astra_gate":          {},
	}
	for argument := range arguments {
		if !allowed[request.Name][argument] {
			return nil, &rpcError{Code: -32602, Message: "Unknown argument: " + argument}
		}
	}

	var value any
	var err error
	switch request.Name {
	case "astra_check_diff":
		var mode string
		if err = decodeRequired(arguments, "mode", &mode); err == nil {
			var base string
			base, err = decodeOptionalString(arguments, "base")
			if err == nil {
				value, err = server.checkDiff(mode, base)
			}
		}
	case "astra_blast_radius":
		var file string
		var symbol string
		var line int
		if err = decodeRequired(arguments, "file", &file); err == nil {
			if raw, ok := arguments["symbol"]; ok {
				err = json.Unmarshal(raw, &symbol)
			}
			if err == nil {
				if raw, ok := arguments["line"]; ok {
					err = json.Unmarshal(raw, &line)
				}
			}
			if err == nil && ((symbol == "") == (line == 0) || line < 0) {
				err = errors.New("provide exactly one of symbol or positive line")
			}
			if err == nil {
				var safeFile string
				safeFile, err = server.resolveFile(file)
				if err == nil {
					relative, relErr := filepath.Rel(server.root, safeFile)
					if relErr != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
						err = errors.New("file is outside the repository root")
					} else {
						value, err = analyzer.BlastRadius(server.root, filepath.ToSlash(relative), symbol, line)
					}
				}
			}
		}
	case "astra_list_routes":
		if len(arguments) != 0 {
			err = errors.New("astra_list_routes takes no arguments")
		} else {
			value, err = server.listRoutes()
		}
	case "astra_explain_route":
		var method, path string
		if err = decodeRequired(arguments, "method", &method); err == nil {
			err = decodeRequired(arguments, "path", &path)
		}
		if err == nil {
			value, err = analyzer.ExplainRoute(server.root, method, path)
		}
	case "astra_gate":
		if len(arguments) != 0 {
			err = errors.New("astra_gate takes no arguments")
		} else {
			value, err = server.gate()
		}
	default:
		return nil, &rpcError{Code: -32602, Message: "Unknown tool: " + request.Name}
	}
	if err != nil {
		return nil, &rpcError{Code: -32602, Message: err.Error()}
	}
	return makeToolResult(value)
}

func (server *Server) checkDiff(mode, base string) (checkReport, error) {
	args := []string{"diff", "--no-ext-diff", "--unified=0"}
	switch mode {
	case "staged":
		if base != "" {
			return checkReport{}, errors.New("base is only valid when mode is base")
		}
		args = append(args, "--cached")
	case "working":
		if base != "" {
			return checkReport{}, errors.New("base is only valid when mode is base")
		}
		args = append(args, "HEAD")
	case "base":
		if base == "" || strings.HasPrefix(base, "-") || strings.ContainsAny(base, "\x00\r\n") {
			return checkReport{}, errors.New("mode base requires a valid base ref")
		}
		args = append(args, base)
	default:
		return checkReport{}, errors.New("mode must be staged, working, or base")
	}
	diffText, err := gitOutput(server.root, args...)
	if err != nil {
		return checkReport{}, fmt.Errorf("read git diff: %w", err)
	}
	changes, err := diff.Parse(strings.NewReader(diffText))
	if err != nil {
		return checkReport{}, fmt.Errorf("parse git diff: %w", err)
	}
	config, err := policy.Load(server.root)
	if err != nil {
		return checkReport{}, err
	}
	changes = config.FilterChanges(changes)
	report, err := analyzer.AnalyzeDiff(server.root, changes)
	if err != nil {
		return checkReport{}, fmt.Errorf("analyze repository diff: %w", err)
	}
	result := checkReport{
		ChangedFiles: len(changes), HasChanges: len(changes) > 0,
		Routes: report.Routes, AffectedRoutes: report.AffectedRoutes, Warnings: report.Warnings,
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return checkReport{}, fmt.Errorf("encode analysis report: %w", err)
	}
	server.latestJSON = encoded
	return result, nil
}

func (server *Server) listRoutes() (*analyzer.Report, error) {
	report, err := analyzer.Analyze(server.root)
	if err != nil {
		return nil, fmt.Errorf("analyze routes: %w", err)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("encode route report: %w", err)
	}
	server.latestJSON = raw
	return report, nil
}

func (server *Server) gate() (gateReport, error) {
	report, err := server.checkDiff("working", "")
	if err != nil {
		return gateReport{}, err
	}
	config, err := policy.Load(server.root)
	if err != nil {
		return gateReport{}, err
	}
	result := gateReport{
		Status: "pass", Violations: make([]string, 0), Report: report,
	}
	result.Violations = config.Violations(&analyzer.Report{AffectedRoutes: report.AffectedRoutes})
	if len(result.Violations) > 0 {
		result.Status = "fail"
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return gateReport{}, fmt.Errorf("encode gate report: %w", err)
	}
	server.latestJSON = encoded
	return result, nil
}

func (server *Server) readResource(params json.RawMessage) (any, *rpcError) {
	var request struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(params, &request); err != nil || request.URI == "" {
		return nil, &rpcError{Code: -32602, Message: "Invalid resources/read parameters"}
	}
	if request.URI != "astra://report/latest" {
		return nil, &rpcError{Code: -32602, Message: "Unknown resource URI"}
	}
	if len(server.latestJSON) == 0 {
		return nil, &rpcError{Code: -32002, Message: "No analysis report is available yet"}
	}
	return map[string]any{"contents": []map[string]any{{
		"uri": request.URI, "mimeType": "application/json", "text": string(server.latestJSON),
	}}}, nil
}

func (server *Server) resolveFile(input string) (string, error) {
	if input == "" || strings.ContainsRune(input, '\x00') {
		return "", errors.New("file path is empty or invalid")
	}
	path := input
	if !filepath.IsAbs(path) {
		path = filepath.Join(server.root, filepath.FromSlash(path))
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve file path: %w", err)
	}
	relative, err := filepath.Rel(server.root, absolute)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("file is outside the repository root")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve repository file: %w", err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("resolve repository file path: %w", err)
	}
	relative, err = filepath.Rel(server.root, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("file resolves outside the repository root")
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("stat repository file: %w", err)
	}
	if info.IsDir() {
		return "", errors.New("file path must identify a file")
	}
	return resolved, nil
}

func makeToolResult(value any) (toolResult, *rpcError) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return toolResult{}, &rpcError{Code: -32603, Message: "Could not encode tool result"}
	}
	if len(encoded) > maxOutputBytes/2 {
		return toolResult{}, &rpcError{Code: -32603, Message: "Tool result exceeds the output size limit"}
	}
	var structured any
	if err := json.Unmarshal(encoded, &structured); err != nil {
		return toolResult{}, &rpcError{Code: -32603, Message: "Could not prepare structured tool result"}
	}
	return toolResult{
		Content:           []toolContent{{Type: "text", Text: string(encoded)}},
		StructuredContent: structured,
	}, nil
}

func decodeRequired(arguments map[string]json.RawMessage, name string, target any) error {
	raw, ok := arguments[name]
	if !ok {
		return fmt.Errorf("missing required argument %q", name)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return fmt.Errorf("invalid argument %q: %w", name, err)
	}
	return nil
}

func decodeOptionalString(arguments map[string]json.RawMessage, name string) (string, error) {
	raw, ok := arguments[name]
	if !ok {
		return "", nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("invalid argument %q: %w", name, err)
	}
	return value, nil
}

func requestID(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return json.RawMessage("null")
	}
	return id
}

func isNotification(id json.RawMessage) bool {
	return len(id) == 0
}

func validRequestID(id json.RawMessage) bool {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(id))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return false
	}
	switch value.(type) {
	case nil, string, json.Number:
		return true
	default:
		return false
	}
}

func validParams(params json.RawMessage) bool {
	if len(params) == 0 {
		return true
	}
	trimmed := bytes.TrimSpace(params)
	return len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')
}

func gitOutput(root string, args ...string) (string, error) {
	commandArgs := append([]string{"-C", root}, args...)
	command := exec.Command("git", commandArgs...)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s",
			strings.Join(commandArgs[2:], " "), err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}
