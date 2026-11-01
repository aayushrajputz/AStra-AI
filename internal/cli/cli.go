package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/astra-ai/astra/bench"
	"github.com/astra-ai/astra/internal/ai"
	"github.com/astra-ai/astra/internal/analyzer"
	"github.com/astra-ai/astra/internal/diff"
	"github.com/astra-ai/astra/internal/mcp"
	"github.com/astra-ai/astra/internal/policy"
)

type checkOutput struct {
	ChangedFiles   int                    `json:"changed_files"`
	HasChanges     bool                   `json:"has_changes"`
	Routes         []analyzer.Route       `json:"routes"`
	AffectedRoutes []analyzer.RouteImpact `json:"affected_routes"`
	Warnings       []analyzer.Warning     `json:"warnings,omitempty"`
	Status         string                 `json:"status,omitempty"`
	Violations     []string               `json:"violations,omitempty"`
	NeedsReview    []string               `json:"needs_review,omitempty"`
	ActiveWaivers  []policy.Waiver        `json:"active_waivers,omitempty"`
	SeverityRules  map[string]string      `json:"severity_rules,omitempty"`
	AIExplanation  *ai.Explanation        `json:"ai_explanation,omitempty"`
	AIDryRun       *aiDryRunPreview       `json:"ai_dry_run_preview,omitempty"`
}

var ErrGateFailed = errors.New("AStra gate failed")

func ExitCode(err error) int {
	if errors.Is(err, ErrGateFailed) {
		return 1
	}
	if err != nil {
		return 2
	}
	return 0
}

type aiDryRunPreview struct {
	Method  string          `json:"method"`
	URL     string          `json:"url"`
	Headers http.Header     `json:"headers"`
	Body    json.RawMessage `json:"body"`
}

func Run(args []string, stdout, stderr io.Writer) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	return runAt(args, stdout, stderr, cwd)
}

func runAt(args []string, stdout, stderr io.Writer, cwd string) error {
	if len(args) == 0 {
		printUsage(stderr)
		return errors.New("missing command")
	}
	switch args[0] {
	case "mcp":
		if len(args) != 1 {
			return fmt.Errorf("mcp does not accept arguments")
		}
		server, err := mcp.NewServer(cwd)
		if err != nil {
			return err
		}
		return server.Serve(os.Stdin, stdout)
	case "bench":
		if len(args) != 1 {
			return fmt.Errorf("bench does not accept arguments")
		}
		_, err := bench.Run(stdout)
		return err
	case "check":
		return runCheck(args[1:], stdout, cwd)
	case "list-routes":
		return runListRoutes(args[1:], stdout, cwd)
	case "install-hook":
		return installHook(args[1:], stdout, cwd)
	case "help", "--help", "-h":
		printUsage(stdout)
		return nil
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runCheck(args []string, stdout io.Writer, cwd string) error {
	flags := flag.NewFlagSet("check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	staged := flags.Bool("staged", false, "analyze staged changes only")
	base := flags.String("base", "", "compare the working tree against a git ref")
	asJSON := flags.Bool("json", false, "write the report as JSON")
	gate := flags.Bool("gate", false, "apply .astrarc.json fail-on policy and fail on violations")
	aiProvider := flags.String("ai-provider", "", "opt in to AI explanations (openai-compatible or anthropic)")
	aiModel := flags.String("ai-model", "", "model name for the selected AI provider")
	aiEndpoint := flags.String("ai-endpoint", "", "override the provider API endpoint")
	aiDryRun := flags.Bool("ai-dry-run", false, "print a credential-redacted AI request preview without sending it")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if *staged && *base != "" {
		return errors.New("--staged and --base cannot be used together")
	}
	if strings.HasPrefix(*base, "-") || strings.ContainsAny(*base, "\x00\r\n") {
		return errors.New("--base must be a Git ref, not an option or multiline value")
	}
	if *aiProvider == "" && (*aiModel != "" || *aiEndpoint != "" || *aiDryRun) {
		return errors.New("--ai-model, --ai-endpoint, and --ai-dry-run require --ai-provider")
	}
	if *aiProvider != "" && strings.TrimSpace(*aiModel) == "" {
		return errors.New("--ai-model is required when --ai-provider is selected")
	}
	var apiKey string
	if *aiProvider != "" {
		key, keyErr := aiAPIKey(*aiProvider)
		if keyErr != nil {
			return keyErr
		}
		apiKey = key
	}

	root, err := gitOutput(cwd, "rev-parse", "--show-toplevel")
	if err != nil {
		return fmt.Errorf("find git repository: %w", err)
	}
	root = strings.TrimSpace(root)
	config, err := policy.Load(root)
	if err != nil {
		return err
	}
	diffArgs := []string{"diff", "--no-ext-diff", "--unified=0"}
	switch {
	case *staged:
		diffArgs = append(diffArgs, "--cached")
	case *base != "":
		diffArgs = append(diffArgs, *base)
	default:
		diffArgs = append(diffArgs, "HEAD")
	}
	diffText, err := gitOutput(root, diffArgs...)
	if err != nil {
		return fmt.Errorf("read git diff: %w", err)
	}
	changes, err := diff.Parse(strings.NewReader(diffText))
	if err != nil {
		return fmt.Errorf("parse git diff: %w", err)
	}
	changes = config.FilterChanges(changes)
	cacheDir, err := analyzer.DefaultCacheDir()
	if err != nil {
		return fmt.Errorf("resolve AStra parse cache: %w", err)
	}
	var report *analyzer.Report
	if *staged {
		if len(changes) == 0 && *gate {
			report = &analyzer.Report{
				Routes: []analyzer.Route{}, AffectedRoutes: []analyzer.RouteImpact{},
				Warnings: []analyzer.Warning{},
			}
		} else {
			overrides, err := stagedSnapshot(root)
			if err != nil {
				return fmt.Errorf("read staged repository snapshot: %w", err)
			}
			report, err = analyzer.AnalyzeDiffWithContent(root, cacheDir, changes, overrides, nil)
		}
	} else {
		report, err = analyzer.AnalyzeDiffWithCache(root, changes, cacheDir)
	}
	if err != nil {
		return fmt.Errorf("analyze repository: %w", err)
	}
	result := checkOutput{
		ChangedFiles: len(changes), HasChanges: len(changes) > 0,
		Routes: report.Routes, AffectedRoutes: report.AffectedRoutes,
		Warnings: report.Warnings,
	}
	if *gate {
		gateResult := config.Evaluate(report)
		result.Status = gateResult.Status
		result.Violations = gateResult.Violations
		result.NeedsReview = gateResult.NeedsReview
		result.ActiveWaivers = gateResult.ActiveWaivers
		result.SeverityRules = config.SeverityRules
	}
	var aiErr error
	if *aiProvider != "" {
		input := ai.BuildInput(changes, report.AffectedRoutes)
		aiConfig := ai.Config{
			Provider: *aiProvider,
			Model:    *aiModel,
			APIKey:   apiKey,
			Endpoint: *aiEndpoint,
		}
		if *aiDryRun {
			preview, err := ai.BuildConfiguredRequest(aiConfig, input)
			if err != nil {
				return err
			}
			result.AIDryRun = &aiDryRunPreview{
				Method: preview.Method, URL: preview.URL, Headers: preview.Headers,
				Body: append(json.RawMessage(nil), preview.BodyBytes...),
			}
		} else {
			explanation, err := ai.Explain(context.Background(), aiConfig, input)
			if err != nil {
				aiErr = fmt.Errorf("AI explanation failed; deterministic analysis is unchanged: %w", err)
			} else {
				result.AIExplanation = &explanation
			}
		}
	}
	if *asJSON {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(result); err != nil {
			return err
		}
	} else {
		if err := printCheck(stdout, result); err != nil {
			return err
		}
		if result.AIDryRun != nil {
			if _, err := fmt.Fprintln(stdout, "AI dry-run preview (no request sent):"); err != nil {
				return err
			}
			encoder := json.NewEncoder(stdout)
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(result.AIDryRun); err != nil {
				return err
			}
		}
		if result.AIExplanation != nil {
			if _, err := fmt.Fprintf(stdout, "AI explanation: %s\n", result.AIExplanation.Summary); err != nil {
				return err
			}
			for _, route := range result.AIExplanation.Routes {
				if _, err := fmt.Fprintf(stdout, "- %s %s: %s\n", route.Method, route.Path, route.Explanation); err != nil {
					return err
				}
			}
		}
	}
	var commandErrors []error
	if *gate && result.Status == "fail" {
		commandErrors = append(commandErrors, ErrGateFailed)
	}
	if aiErr != nil {
		commandErrors = append(commandErrors, aiErr)
	}
	if len(commandErrors) != 0 {
		return errors.Join(commandErrors...)
	}
	return nil
}

func aiAPIKey(provider string) (string, error) {
	switch provider {
	case ai.OpenAICompatible:
		return os.Getenv("OPENAI_API_KEY"), nil
	case ai.Anthropic:
		return os.Getenv("ANTHROPIC_API_KEY"), nil
	default:
		return "", fmt.Errorf("unsupported AI provider %q", provider)
	}
}

func runListRoutes(args []string, stdout io.Writer, cwd string) error {
	flags := flag.NewFlagSet("list-routes", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	asJSON := flags.Bool("json", false, "write the route list as JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	root, err := gitOutput(cwd, "rev-parse", "--show-toplevel")
	if err != nil {
		return fmt.Errorf("find git repository: %w", err)
	}
	cacheDir, err := analyzer.DefaultCacheDir()
	if err != nil {
		return fmt.Errorf("resolve AStra parse cache: %w", err)
	}
	report, err := analyzer.AnalyzeWithCache(strings.TrimSpace(root), cacheDir)
	if err != nil {
		return fmt.Errorf("analyze repository: %w", err)
	}
	if *asJSON {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}
	for _, route := range report.Routes {
		if _, err := fmt.Fprintf(stdout, "%-7s %-32s %s:%d [%s]\n",
			route.Method, route.Path, route.File, route.Line, route.Confidence); err != nil {
			return err
		}
	}
	for _, warning := range report.Warnings {
		if _, err := fmt.Fprintf(stdout, "warning: %s:%d: %s\n",
			warning.File, warning.Line, warning.Message); err != nil {
			return err
		}
	}
	return nil
}

func installHook(args []string, stdout io.Writer, cwd string) error {
	if len(args) != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(args, " "))
	}
	root, err := gitOutput(cwd, "rev-parse", "--show-toplevel")
	if err != nil {
		return fmt.Errorf("find git repository: %w", err)
	}
	root = strings.TrimSpace(root)
	hookPath, err := gitOutput(root, "rev-parse", "--git-path", "hooks/pre-commit")
	if err != nil {
		return fmt.Errorf("find pre-commit hook path: %w", err)
	}
	hookPath = strings.TrimSpace(hookPath)
	if !filepath.IsAbs(hookPath) {
		hookPath = filepath.Join(root, hookPath)
	}
	if err := os.MkdirAll(filepath.Dir(hookPath), 0o755); err != nil {
		return fmt.Errorf("create hook directory: %w", err)
	}
	file, err := os.OpenFile(hookPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("pre-commit hook already exists at %s; refusing to overwrite it", hookPath)
		}
		return fmt.Errorf("create pre-commit hook: %w", err)
	}
	if _, err := io.WriteString(file, "#!/bin/sh\nastra check --staged --gate\nstatus=$?\nif [ \"$status\" -ne 0 ]; then\n  echo \"AStra pre-commit gate failed; --no-verify bypasses this hook. CI remains the authoritative merge gate.\" >&2\nfi\nexit \"$status\"\n"); err != nil {
		file.Close()
		os.Remove(hookPath)
		return fmt.Errorf("write pre-commit hook: %w", err)
	}
	if err := file.Close(); err != nil {
		os.Remove(hookPath)
		return fmt.Errorf("close pre-commit hook: %w", err)
	}
	_, err = fmt.Fprintf(stdout, "Installed pre-commit hook at %s\n", hookPath)
	return err
}

func gitOutput(cwd string, args ...string) (string, error) {
	commandArgs := append([]string{"-C", cwd}, args...)
	command := exec.Command("git", commandArgs...)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %w: %s", strings.Join(commandArgs, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func stagedSnapshot(root string) (map[string][]byte, error) {
	command := exec.Command("git", "-C", root, "ls-files", "--stage", "-z")
	indexEntries, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w", err)
	}
	type stagedFile struct {
		path string
		hash string
	}
	files := make([]stagedFile, 0)
	input := bytes.NewBuffer(nil)
	for _, entry := range bytes.Split(indexEntries, []byte{0}) {
		if len(entry) == 0 {
			continue
		}
		metadataEnd := bytes.IndexByte(entry, '\t')
		if metadataEnd < 0 {
			return nil, errors.New("malformed git index entry")
		}
		fields := strings.Fields(string(entry[:metadataEnd]))
		if len(fields) != 3 {
			return nil, errors.New("malformed git index metadata")
		}
		if fields[2] != "0" {
			return nil, fmt.Errorf("unmerged index entry for %q", string(entry[metadataEnd+1:]))
		}
		relative := string(entry[metadataEnd+1:])
		if err := validateRepoRelativePath(relative); err != nil {
			return nil, fmt.Errorf("invalid staged path %q: %w", relative, err)
		}
		if !isSourcePath(relative) {
			continue
		}
		if fields[0] != "100644" && fields[0] != "100755" {
			continue
		}
		files = append(files, stagedFile{path: relative, hash: fields[1]})
		fmt.Fprintln(input, fields[1])
	}
	if len(files) == 0 {
		return map[string][]byte{}, nil
	}
	command = exec.Command("git", "-C", root, "cat-file", "--batch")
	command.Stdin = input
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("git cat-file --batch: %w", err)
	}
	reader := bufio.NewReader(bytes.NewReader(output))
	contents := make(map[string][]byte, len(files))
	for _, file := range files {
		header, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("read staged blob header for %s: %w", file.path, err)
		}
		fields := strings.Fields(header)
		if len(fields) != 3 || fields[1] != "blob" {
			return nil, fmt.Errorf("invalid staged blob header for %s: %q", file.path, strings.TrimSpace(header))
		}
		size, err := strconv.Atoi(fields[2])
		if err != nil || size < 0 {
			return nil, fmt.Errorf("invalid staged blob size for %s", file.path)
		}
		content := make([]byte, size)
		if _, err := io.ReadFull(reader, content); err != nil {
			return nil, fmt.Errorf("read staged blob for %s: %w", file.path, err)
		}
		if separator, err := reader.ReadByte(); err != nil || separator != '\n' {
			return nil, fmt.Errorf("invalid staged blob separator for %s", file.path)
		}
		contents[file.path] = content
	}
	return contents, nil
}

func isSourcePath(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go":
		return true
	default:
		return false
	}
}

func validateRepoRelativePath(path string) error {
	if path == "" || filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
		return errors.New("path must be repository-relative")
	}
	clean := filepath.Clean(filepath.FromSlash(path))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return errors.New("path escapes repository root")
	}
	return nil
}

func printCheck(stdout io.Writer, result checkOutput) error {
	if _, err := fmt.Fprintf(stdout, "Analyzed %d route(s); %d changed file(s).\n",
		len(result.Routes), result.ChangedFiles); err != nil {
		return err
	}
	if len(result.AffectedRoutes) == 0 {
		if _, err := fmt.Fprintln(stdout, "No affected routes detected."); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintf(stdout, "Potentially affected route(s): %d\n", len(result.AffectedRoutes)); err != nil {
			return err
		}
		for _, impact := range result.AffectedRoutes {
			if _, err := fmt.Fprintf(stdout, "- %s %s (%s:%d, %s)\n",
				impact.Route.Method, impact.Route.Path, impact.Route.File, impact.Route.Line,
				impact.Confidence); err != nil {
				return err
			}
			if len(impact.Chain) > 0 {
				if _, err := fmt.Fprintf(stdout, "  chain: %s\n", strings.Join(impact.Chain, " -> ")); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintf(stdout, "  reason: %s\n", impact.Reason); err != nil {
				return err
			}
			if impact.Resolution != "" {
				if _, err := fmt.Fprintf(stdout, "  resolution: %s\n", impact.Resolution); err != nil {
					return err
				}
			}
			for _, callSite := range impact.CallSites {
				if _, err := fmt.Fprintf(stdout, "  incompatible caller: %s:%d\n", callSite.File, callSite.Line); err != nil {
					return err
				}
			}
		}
	}
	for _, warning := range result.Warnings {
		if _, err := fmt.Fprintf(stdout, "warning: %s:%d: %s\n",
			warning.File, warning.Line, warning.Message); err != nil {
			return err
		}
	}
	if result.Status != "" {
		if _, err := fmt.Fprintf(stdout, "AStra gate: %s\n", result.Status); err != nil {
			return err
		}
		for _, violation := range result.Violations {
			if _, err := fmt.Fprintf(stdout, "violation: %s\n", violation); err != nil {
				return err
			}
		}
		for _, item := range result.NeedsReview {
			if _, err := fmt.Fprintf(stdout, "needs review: %s\n", item); err != nil {
				return err
			}
		}
		for _, waiver := range result.ActiveWaivers {
			if _, err := fmt.Fprintf(stdout, "active waiver: %s%s (owner: %s, expires: %s, reason: %s)\n",
				waiver.Symbol, waiver.Route, waiver.Owner, waiver.Expires, waiver.Reason); err != nil {
				return err
			}
		}
	}
	return nil
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, `AStra - local route impact analysis

Usage:
  astra mcp
  astra check [--staged | --base REF] [--json] [--gate]
              [--ai-provider PROVIDER --ai-model MODEL] [--ai-dry-run]
  astra list-routes [--json]
  astra bench
  astra install-hook
  astra help`)
}
