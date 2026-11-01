package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/astra-ai/astra/internal/analyzer"
	"github.com/astra-ai/astra/internal/diff"
)

type Config struct {
	IgnoredPaths  []string          `json:"ignored_paths"`
	FailOn        []string          `json:"-"`
	SeverityRules map[string]string `json:"severity_rules"`
	failOnSet     bool
}

type diskConfig struct {
	IgnoredPaths     []string          `json:"ignored_paths"`
	FailOn           json.RawMessage   `json:"fail-on"`
	FailOnSnake      json.RawMessage   `json:"fail_on"`
	SeverityRules    map[string]string `json:"severity_rules"`
	SeverityRulesAlt map[string]string `json:"severity-rules"`
}

var validSeverities = map[string]bool{
	"breaking": true, "potential": true, "non-breaking": true, "uncertain": true,
}

var validDisplaySeverities = map[string]bool{
	"critical": true, "high": true, "medium": true, "low": true, "info": true,
	"error": true, "warning": true, "notice": true,
}

func Load(root string) (Config, error) {
	config := Config{FailOn: []string{"breaking"}, SeverityRules: make(map[string]string)}
	raw, err := os.ReadFile(filepath.Join(root, ".astrarc.json"))
	if errors.Is(err, os.ErrNotExist) {
		return config, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("read .astrarc.json: %w", err)
	}
	var disk diskConfig
	if err := json.Unmarshal(raw, &disk); err != nil {
		return Config{}, fmt.Errorf("parse .astrarc.json: %w", err)
	}
	config.IgnoredPaths = disk.IgnoredPaths
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
			return Config{}, fmt.Errorf("fail-on must be a string or list of strings, not null")
		}
		if err := json.Unmarshal(failOnRaw, &config.FailOn); err != nil {
			var single string
			if singleErr := json.Unmarshal(failOnRaw, &single); singleErr != nil {
				return Config{}, fmt.Errorf("fail-on must be a string or list of strings")
			}
			config.FailOn = []string{single}
		}
	}
	if !config.failOnSet {
		config.FailOn = []string{"breaking"}
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
