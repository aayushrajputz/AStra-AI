package bench

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/astra-ai/astra/internal/analyzer"
	"github.com/astra-ai/astra/internal/diff"
)

//go:embed testdata/**
var corpus embed.FS

type corpusFile struct {
	Name   string       `json:"name"`
	Source string       `json:"source"`
	Cases  []corpusCase `json:"cases"`
}

type corpusCase struct {
	ID              string   `json:"id"`
	Description     string   `json:"description"`
	Directory       string   `json:"directory"`
	BreakingRoutes  []string `json:"breaking_routes"`
	KnownRoutes     []string `json:"known_routes"`
	UncertainRoutes []string `json:"uncertain_routes,omitempty"`
}

type Metrics struct {
	Corpus            string  `json:"corpus"`
	Cases             int     `json:"cases"`
	TruePositives     int     `json:"true_positives"`
	FalsePositives    int     `json:"false_positives"`
	FalseNegatives    int     `json:"false_negatives"`
	TrueNegatives     int     `json:"true_negatives"`
	Precision         float64 `json:"precision_percent"`
	Recall            float64 `json:"recall_percent"`
	FalsePositiveRate float64 `json:"false_positive_rate_percent"`
	Warnings          int     `json:"warnings"`
}

func Run(output io.Writer) (Metrics, error) {
	raw, err := corpus.ReadFile("testdata/corpus.json")
	if err != nil {
		return Metrics{}, fmt.Errorf("read embedded benchmark corpus: %w", err)
	}
	var collection corpusFile
	if err := json.Unmarshal(raw, &collection); err != nil {
		return Metrics{}, fmt.Errorf("decode benchmark corpus: %w", err)
	}
	if len(collection.Cases) == 0 {
		return Metrics{}, fmt.Errorf("benchmark corpus has no cases")
	}
	if _, err := fmt.Fprintf(output, "Corpus: %s\nSource: %s\nDate: %s\n",
		collection.Name, collection.Source, time.Now().Format("2006-01-02")); err != nil {
		return Metrics{}, err
	}

	metrics := Metrics{Corpus: collection.Name, Cases: len(collection.Cases)}
	for _, testCase := range collection.Cases {
		caseMetrics, warnings, details, err := runCase(testCase)
		if err != nil {
			return Metrics{}, fmt.Errorf("benchmark case %s: %w", testCase.ID, err)
		}
		metrics.TruePositives += caseMetrics.TruePositives
		metrics.FalsePositives += caseMetrics.FalsePositives
		metrics.FalseNegatives += caseMetrics.FalseNegatives
		metrics.TrueNegatives += caseMetrics.TrueNegatives
		metrics.Warnings += warnings
		if _, err := fmt.Fprintf(output, "\n%s: %s\n  %s\n",
			testCase.ID, testCase.Description, details); err != nil {
			return Metrics{}, err
		}
	}

	metrics.Precision = percent(metrics.TruePositives, metrics.TruePositives+metrics.FalsePositives)
	metrics.Recall = percent(metrics.TruePositives, metrics.TruePositives+metrics.FalseNegatives)
	metrics.FalsePositiveRate = percent(metrics.FalsePositives, metrics.FalsePositives+metrics.TrueNegatives)
	if _, err := fmt.Fprintf(output,
		"\nBaseline (route-level; every reported impact counts as a detection):\n"+
			"  TP=%d FP=%d FN=%d TN=%d\n"+
			"  Precision: %.1f%%\n  Recall: %.1f%%\n  False-positive rate: %.1f%%\n"+
			"  Analyzer warnings: %d\n"+
			"Flags: ~ heuristic finding; ⚠ dynamic/unresolved uncertainty.\n",
		metrics.TruePositives, metrics.FalsePositives, metrics.FalseNegatives, metrics.TrueNegatives,
		metrics.Precision, metrics.Recall, metrics.FalsePositiveRate, metrics.Warnings); err != nil {
		return Metrics{}, err
	}
	return metrics, nil
}

func runCase(testCase corpusCase) (Metrics, int, string, error) {
	beforeDir := "testdata/" + testCase.Directory + "/before"
	afterDir := "testdata/" + testCase.Directory + "/after"
	before, err := readTree(beforeDir)
	if err != nil {
		return Metrics{}, 0, "", err
	}
	after, err := readTree(afterDir)
	if err != nil {
		return Metrics{}, 0, "", err
	}

	root, err := os.MkdirTemp("", "astra-bench-"+testCase.ID+"-")
	if err != nil {
		return Metrics{}, 0, "", fmt.Errorf("create temporary repository: %w", err)
	}
	defer os.RemoveAll(root)
	if err := git(root, "init", "-q"); err != nil {
		return Metrics{}, 0, "", err
	}
	if err := git(root, "config", "user.name", "AStra Benchmark"); err != nil {
		return Metrics{}, 0, "", err
	}
	if err := git(root, "config", "user.email", "astra-bench@example.invalid"); err != nil {
		return Metrics{}, 0, "", err
	}
	if err := writeTree(root, before); err != nil {
		return Metrics{}, 0, "", fmt.Errorf("write before state: %w", err)
	}
	if err := git(root, "add", "-A"); err != nil {
		return Metrics{}, 0, "", err
	}
	if err := git(root, "commit", "-q", "-m", "fixture baseline"); err != nil {
		return Metrics{}, 0, "", err
	}
	if err := replaceTree(root, before, after); err != nil {
		return Metrics{}, 0, "", fmt.Errorf("write after state: %w", err)
	}
	if err := git(root, "add", "-A"); err != nil {
		return Metrics{}, 0, "", err
	}
	if err := git(root, "commit", "-q", "-m", "fixture change"); err != nil {
		return Metrics{}, 0, "", err
	}
	diffText, err := gitOutput(root, "diff", "--no-ext-diff", "--unified=0", "HEAD^", "HEAD")
	if err != nil {
		return Metrics{}, 0, "", fmt.Errorf("read fixture commit diff: %w", err)
	}
	changes, err := diff.Parse(strings.NewReader(diffText))
	if err != nil {
		return Metrics{}, 0, "", fmt.Errorf("parse fixture commit diff: %w", err)
	}
	report, err := analyzer.AnalyzeDiff(root, changes)
	if err != nil {
		return Metrics{}, 0, "", fmt.Errorf("analyze fixture commit: %w", err)
	}

	known := stringSet(testCase.KnownRoutes)
	for _, route := range report.Routes {
		known[routeID(route)] = true
	}
	expected := stringSet(testCase.BreakingRoutes)
	for route := range expected {
		known[route] = true
	}
	predicted := make(map[string]bool)
	predictionLabels := make(map[string]string)
	for _, impact := range report.AffectedRoutes {
		key := routeID(impact.Route)
		predicted[key] = true
		prefix := "~"
		if impact.Confidence == "uncertain" {
			prefix = "⚠"
		}
		predictionLabels[key] = prefix + key + " (" + impact.Severity + ")"
		known[key] = true
	}

	result := Metrics{Cases: 1}
	for route := range known {
		_, isExpected := expected[route]
		if predicted[route] && isExpected {
			result.TruePositives++
		} else if predicted[route] {
			result.FalsePositives++
		} else if isExpected {
			result.FalseNegatives++
		} else {
			result.TrueNegatives++
		}
	}

	labels := make([]string, 0, len(predictionLabels))
	for _, label := range predictionLabels {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	warningCount := len(report.Warnings)
	for _, warning := range report.Warnings {
		labels = append(labels, fmt.Sprintf("⚠ %s:%d %s", warning.File, warning.Line, warning.Message))
	}
	for _, route := range testCase.UncertainRoutes {
		if !predicted[route] {
			labels = append(labels, "⚠ missed dynamic route: "+route)
		}
	}
	if len(labels) == 0 {
		labels = append(labels, "no route impacts or uncertainty warnings")
	}
	details := fmt.Sprintf("TP=%d FP=%d FN=%d TN=%d; %s",
		result.TruePositives, result.FalsePositives, result.FalseNegatives, result.TrueNegatives,
		strings.Join(labels, "; "))
	return result, warningCount, details, nil
}

func readTree(directory string) (map[string][]byte, error) {
	files := make(map[string][]byte)
	err := fs.WalkDir(corpus, directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		content, err := corpus.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(relative)] = content
		return nil
	})
	return files, err
}

func writeTree(root string, files map[string][]byte) error {
	for path, content := range files {
		destination := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(destination, content, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func replaceTree(root string, before, after map[string][]byte) error {
	for path := range before {
		if _, exists := after[path]; exists {
			continue
		}
		if err := os.Remove(filepath.Join(root, filepath.FromSlash(path))); err != nil {
			return err
		}
	}
	return writeTree(root, after)
}

func git(root string, args ...string) error {
	_, err := gitOutput(root, args...)
	return err
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

func routeID(route analyzer.Route) string {
	return route.Method + " " + route.Path
}

func stringSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}

func percent(numerator, denominator int) float64 {
	if denominator == 0 {
		return 0
	}
	return float64(numerator) * 100 / float64(denominator)
}
