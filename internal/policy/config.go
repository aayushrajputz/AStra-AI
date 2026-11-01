package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/astra-ai/astra/internal/analyzer"
	"github.com/astra-ai/astra/internal/diff"
)

type Config struct {
	IgnoredPaths           []string          `json:"ignored_paths"`
	FailOn                 []string          `json:"-"`
	SeverityRules          map[string]string `json:"severity_rules"`
	GateMode               string            `json:"fail_on"`
	RouteSeverity          map[string]string `json:"route_severity,omitempty"`
	AllowHeuristicFailures bool              `json:"allow_heuristic_failures"`
	Waivers                []Waiver          `json:"waivers,omitempty"`
	legacyFailOn           bool
	failOnSet              bool
}

type Waiver struct {
	Symbol  string `json:"symbol,omitempty"`
	Route   string `json:"route,omitempty"`
	Reason  string `json:"reason"`
	Owner   string `json:"owner"`
	Expires string `json:"expires"`
}

type GateResult struct {
	Status        string   `json:"status"`
	Violations    []string `json:"violations"`
	NeedsReview   []string `json:"needs_review"`
	ActiveWaivers []Waiver `json:"active_waivers"`
}

type diskConfig struct {
	IgnoredPaths     []string          `json:"ignored_paths"`
	IgnorePaths      []string          `json:"ignore_paths"`
	FailOn           json.RawMessage   `json:"fail-on"`
	FailOnSnake      json.RawMessage   `json:"fail_on"`
	SeverityRules    map[string]string `json:"severity_rules"`
	SeverityRulesAlt map[string]string `json:"severity-rules"`
	RouteSeverity    map[string]string `json:"route_severity"`
	RouteSeverityAlt map[string]string `json:"per_route_severity"`
	AllowHeuristic   bool              `json:"allow_heuristic_failures"`
}

var validSeverities = map[string]bool{
	"breaking": true, "potential": true, "non-breaking": true, "uncertain": true,
}

var validDisplaySeverities = map[string]bool{
	"critical": true, "high": true, "medium": true, "low": true, "info": true,
	"error": true, "warning": true, "notice": true,
}

func Load(root string) (Config, error) {
	config := Config{
		FailOn: []string{"breaking"}, GateMode: "unresolved-breaking",
		SeverityRules: make(map[string]string), RouteSeverity: make(map[string]string),
	}
	raw, err := os.ReadFile(filepath.Join(root, ".astrarc.json"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Config{}, fmt.Errorf("read .astrarc.json: %w", err)
	}
	if err == nil {
		var disk diskConfig
		if err := json.Unmarshal(raw, &disk); err != nil {
			return Config{}, fmt.Errorf("parse .astrarc.json: %w", err)
		}
		config.IgnoredPaths = append(disk.IgnoredPaths, disk.IgnorePaths...)
		config.SeverityRules = disk.SeverityRules
		if config.SeverityRules == nil {
			config.SeverityRules = disk.SeverityRulesAlt
		}
		failOnRaw := disk.FailOn
		if len(failOnRaw) == 0 {
			failOnRaw = disk.FailOnSnake
		}
		if len(failOnRaw) > 0 {
			config.failOnSet = true
			if strings.TrimSpace(string(failOnRaw)) == "null" {
				return Config{}, fmt.Errorf("fail_on must be a string or list of strings, not null")
			}
			var mode string
			if err := json.Unmarshal(failOnRaw, &mode); err == nil {
				switch mode {
				case "unresolved-breaking", "any-breaking", "never":
					config.GateMode = mode
					config.FailOn = nil
				case "breaking", "potential", "non-breaking", "uncertain":
					config.FailOn = []string{mode}
					config.legacyFailOn = true
				default:
					return Config{}, fmt.Errorf("unsupported fail_on mode %q", mode)
				}
			} else if err := json.Unmarshal(failOnRaw, &config.FailOn); err == nil {
				config.legacyFailOn = true
			} else {
				return Config{}, fmt.Errorf("fail_on must be a gate mode string or legacy list of severities")
			}
		}
		config.RouteSeverity = disk.RouteSeverity
		if config.RouteSeverity == nil {
			config.RouteSeverity = disk.RouteSeverityAlt
		}
		if config.RouteSeverity == nil {
			config.RouteSeverity = make(map[string]string)
		}
		config.AllowHeuristicFailures = disk.AllowHeuristic
	}
	if err := loadWaivers(root, &config); err != nil {
		return Config{}, err
	}
	if err := config.validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (config Config) validate() error {
	for _, severity := range config.FailOn {
		if !validSeverities[severity] {
			return fmt.Errorf("unsupported fail-on severity %q", severity)
		}
	}
	for severity, display := range config.SeverityRules {
		if !validSeverities[severity] {
			return fmt.Errorf("unsupported severity rule %q", severity)
		}
		if !validDisplaySeverities[display] {
			return fmt.Errorf("unsupported display severity %q for %q", display, severity)
		}
	}
	if config.GateMode != "unresolved-breaking" && config.GateMode != "any-breaking" && config.GateMode != "never" {
		return fmt.Errorf("unsupported gate mode %q", config.GateMode)
	}
	for route, mode := range config.RouteSeverity {
		if strings.TrimSpace(route) == "" || (mode != "unresolved-breaking" && mode != "any-breaking" && mode != "never") {
			return fmt.Errorf("invalid route severity override %q: %q", route, mode)
		}
	}
	for _, pattern := range config.IgnoredPaths {
		if pattern == "" || strings.HasPrefix(pattern, "/") || strings.Contains(pattern, "\\") {
			return fmt.Errorf("invalid ignored path pattern %q: use a repository-relative slash path", pattern)
		}
		for _, segment := range strings.Split(pattern, "/") {
			if segment == "**" {
				continue
			}
			if _, err := path.Match(segment, "placeholder"); err != nil {
				return fmt.Errorf("invalid ignored path pattern %q: %w", pattern, err)
			}
		}
	}
	return nil
}

func (config Config) FailOnSeverities() []string {
	return append([]string(nil), config.FailOn...)
}

func (config Config) DisplaySeverity(severity string) string {
	if display, ok := config.SeverityRules[severity]; ok {
		return display
	}
	return severity
}

func (config Config) IsIgnored(file string) bool {
	file = strings.TrimPrefix(path.Clean(file), "./")
	for _, pattern := range config.IgnoredPaths {
		if globMatch(pattern, file) {
			return true
		}
	}
	return false
}

func loadWaivers(root string, config *Config) error {
	raw, err := os.ReadFile(filepath.Join(root, ".astra-waivers.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read .astra-waivers.json: %w", err)
	}
	var document struct {
		Waivers []Waiver `json:"waivers"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return fmt.Errorf("parse .astra-waivers.json: %w", err)
	}
	for index, waiver := range document.Waivers {
		if (strings.TrimSpace(waiver.Symbol) == "") == (strings.TrimSpace(waiver.Route) == "") ||
			strings.TrimSpace(waiver.Reason) == "" || strings.TrimSpace(waiver.Owner) == "" {
			return fmt.Errorf(".astra-waivers.json waiver %d requires exactly one of symbol or route, plus reason and owner", index)
		}
		if _, err := time.Parse("2006-01-02", waiver.Expires); err != nil {
			return fmt.Errorf(".astra-waivers.json waiver %d expires must be YYYY-MM-DD", index)
		}
	}
	config.Waivers = document.Waivers
	return nil
}

func (config Config) Evaluate(report *analyzer.Report) GateResult {
	result := GateResult{Status: "pass", Violations: []string{}, NeedsReview: []string{}, ActiveWaivers: []Waiver{}}
	today := time.Now().UTC().Format("2006-01-02")
	for _, waiver := range config.Waivers {
		if waiver.Expires < today {
			result.Violations = append(result.Violations,
				fmt.Sprintf("expired waiver for %s%s (owner %s, expired %s)",
					waiver.Symbol, waiver.Route, waiver.Owner, waiver.Expires))
		} else {
			result.ActiveWaivers = append(result.ActiveWaivers, waiver)
		}
	}
	for _, impact := range report.AffectedRoutes {
		routeLabel := impact.Route.Method + " " + impact.Route.Path
		mode := config.RouteSeverity[routeLabel]
		if mode == "" {
			mode = config.GateMode
		}
		if config.legacyFailOn {
			if config.matchingWaiver(impact, today) {
				continue
			}
			if contains(config.FailOn, impact.Severity) {
				result.Violations = append(result.Violations,
					fmt.Sprintf("%s: %s (%s)", routeLabel, impact.Reason, config.DisplaySeverity(impact.Severity)))
			}
			continue
		}
		if impact.Severity != "breaking" || mode == "never" {
			continue
		}
		if config.matchingWaiver(impact, today) {
			continue
		}
		if impact.Confidence != "exact" {
			review := fmt.Sprintf("%s: %s", routeLabel, impact.Reason)
			if config.AllowHeuristicFailures && impact.Resolution == "unresolved" && mode != "never" {
				result.Violations = append(result.Violations, review)
			} else {
				result.NeedsReview = append(result.NeedsReview, review)
			}
			continue
		}
		if mode == "any-breaking" || impact.Resolution == "unresolved" {
			result.Violations = append(result.Violations, fmt.Sprintf("%s: %s", routeLabel, impact.Reason))
		} else if impact.Resolution != "resolved" {
			result.NeedsReview = append(result.NeedsReview, fmt.Sprintf("%s: %s", routeLabel, impact.Reason))
		}
	}
	if len(result.Violations) > 0 {
		result.Status = "fail"
	}
	return result
}

func (config Config) matchingWaiver(impact analyzer.RouteImpact, today string) bool {
	route := impact.Route.Method + " " + impact.Route.Path
	for _, waiver := range config.Waivers {
		if waiver.Expires >= today &&
			((waiver.Symbol != "" && waiver.Symbol == impact.Symbol) ||
				(waiver.Route != "" && waiver.Route == route)) {
			return true
		}
	}
	return false
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func globMatch(pattern, file string) bool {
	patternParts := strings.Split(strings.Trim(pattern, "/"), "/")
	fileParts := strings.Split(strings.Trim(file, "/"), "/")
	memo := make(map[[2]int]bool)
	seen := make(map[[2]int]bool)
	var match func(int, int) bool
	match = func(patternIndex, fileIndex int) bool {
		key := [2]int{patternIndex, fileIndex}
		if seen[key] {
			return memo[key]
		}
		seen[key] = true
		var ok bool
		switch {
		case patternIndex == len(patternParts):
			ok = fileIndex == len(fileParts)
		case patternParts[patternIndex] == "**":
			ok = match(patternIndex+1, fileIndex) ||
				fileIndex < len(fileParts) && match(patternIndex, fileIndex+1)
		case fileIndex < len(fileParts):
			var err error
			var segmentMatch bool
			segmentMatch, err = path.Match(patternParts[patternIndex], fileParts[fileIndex])
			ok = err == nil && segmentMatch && match(patternIndex+1, fileIndex+1)
		}
		memo[key] = ok
		return ok
	}
	return match(0, 0)
}

func (config Config) FilterChanges(changes []diff.File) []diff.File {
	filtered := make([]diff.File, 0, len(changes))
	for _, change := range changes {
		if !config.IsIgnored(change.Path) {
			filtered = append(filtered, change)
		}
	}
	return filtered
}

func (config Config) Violations(report *analyzer.Report) []string {
	violations := make([]string, 0)
	failOn := make(map[string]bool, len(config.FailOn))
	for _, severity := range config.FailOn {
		failOn[severity] = true
	}
	for _, impact := range report.AffectedRoutes {
		if !failOn[impact.Severity] {
			continue
		}
		violations = append(violations, fmt.Sprintf("%s %s: %s (%s)",
			impact.Route.Method, impact.Route.Path, impact.Reason, config.DisplaySeverity(impact.Severity)))
	}
	return violations
}
