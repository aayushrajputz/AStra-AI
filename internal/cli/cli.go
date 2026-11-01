package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/astra-ai/astra/bench"
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
	SeverityRules  map[string]string      `json:"severity_rules,omitempty"`
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
	report, err := analyzer.AnalyzeDiffWithCache(root, changes, cacheDir)
	if err != nil {
		return fmt.Errorf("analyze repository: %w", err)
	}
	result := checkOutput{
		ChangedFiles: len(changes), HasChanges: len(changes) > 0,
		Routes: report.Routes, AffectedRoutes: report.AffectedRoutes,
		Warnings: report.Warnings,
	}
	if *gate {
		result.Violations = config.Violations(report)
		result.Status = "pass"
		if len(result.Violations) > 0 {
			result.Status = "fail"
		}
		result.SeverityRules = config.SeverityRules
	}
	if *asJSON {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(result); err != nil {
			return err
		}
	} else if err := printCheck(stdout, result); err != nil {
		return err
	}
	if *gate && result.Status == "fail" {
		return errors.New("AStra gate failed")
	}
	return nil
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
	if _, err := io.WriteString(file, "#!/bin/sh\nexec astra check --staged\n"); err != nil {
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
	}
	return nil
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, `AStra - local route impact analysis

Usage:
  astra mcp
  astra check [--staged | --base REF] [--json] [--gate]
  astra list-routes [--json]
  astra bench
  astra install-hook
  astra help`)
}
