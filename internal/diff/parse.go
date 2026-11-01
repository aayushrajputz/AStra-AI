package diff

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type Status string

const (
	Added    Status = "added"
	Deleted  Status = "deleted"
	Modified Status = "modified"
	Renamed  Status = "renamed"
)

type ChangeKind string

const (
	AddedChange   ChangeKind = "added"
	DeletedChange ChangeKind = "deleted"
)

type Change struct {
	Kind    ChangeKind `json:"kind"`
	OldLine int        `json:"old_line,omitempty"`
	NewLine int        `json:"new_line,omitempty"`
	Text    string     `json:"text"`
}

type File struct {
	OldPath string   `json:"old_path,omitempty"`
	Path    string   `json:"path"`
	Status  Status   `json:"status"`
	Changes []Change `json:"changes"`
}

type hunk struct {
	oldLine int
	newLine int
	oldLeft int
	newLeft int
}

func Parse(input io.Reader) ([]File, error) {
	reader := bufio.NewReader(input)
	files := make([]File, 0)
	var current *File
	var active *hunk

	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil && readErr != io.EOF {
			return nil, readErr
		}
		if len(line) > 0 {
			line = strings.TrimSuffix(line, "\n")
			line = strings.TrimSuffix(line, "\r")

			switch {
			case strings.HasPrefix(line, "diff --git "):
				if active != nil && (active.oldLeft != 0 || active.newLeft != 0) {
					return nil, fmt.Errorf("incomplete hunk before %q", line)
				}
				if current != nil {
					files = append(files, *current)
				}
				oldPath, newPath, err := parseGitHeader(strings.TrimPrefix(line, "diff --git "))
				if err != nil {
					return nil, err
				}
				current = &File{
					OldPath: oldPath,
					Path:    newPath,
					Status:  Modified,
					Changes: make([]Change, 0),
				}
				active = nil
			case current != nil && strings.HasPrefix(line, "new file mode "):
				current.Status = Added
			case current != nil && strings.HasPrefix(line, "deleted file mode "):
				current.Status = Deleted
			case current != nil && strings.HasPrefix(line, "rename from "):
				current.OldPath = strings.TrimPrefix(line, "rename from ")
				current.Status = Renamed
			case current != nil && strings.HasPrefix(line, "rename to "):
				current.Path = strings.TrimPrefix(line, "rename to ")
				current.Status = Renamed
			case current != nil && strings.HasPrefix(line, "--- "):
				path, err := parseFileHeader(strings.TrimPrefix(line, "--- "))
				if err != nil {
					return nil, err
				}
				if path == "/dev/null" {
					current.Status = Added
				} else if current.OldPath == "" {
					current.OldPath = path
				}
			case current != nil && strings.HasPrefix(line, "+++ "):
				path, err := parseFileHeader(strings.TrimPrefix(line, "+++ "))
				if err != nil {
					return nil, err
				}
				if path == "/dev/null" {
					current.Status = Deleted
				} else {
					current.Path = path
				}
			case current != nil && strings.HasPrefix(line, "@@ "):
				if active != nil && (active.oldLeft != 0 || active.newLeft != 0) {
					return nil, fmt.Errorf("incomplete hunk in %q", current.Path)
				}
				parsed, err := parseHunk(line)
				if err != nil {
					return nil, fmt.Errorf("parse hunk in %q: %w", current.Path, err)
				}
				active = parsed
			case current != nil && active != nil:
				if err := consumeHunkLine(current, active, line); err != nil {
					return nil, fmt.Errorf("parse hunk in %q: %w", current.Path, err)
				}
			}
		}

		if readErr == io.EOF {
			break
		}
	}

	if active != nil && (active.oldLeft != 0 || active.newLeft != 0) {
		path := ""
		if current != nil {
			path = current.Path
		}
		return nil, fmt.Errorf("incomplete hunk in %q", path)
	}
	if current != nil {
		files = append(files, *current)
	}
	return files, nil
}

func parseGitHeader(header string) (string, string, error) {
	oldPath, rest, err := readPathToken(header)
	if err != nil {
		return "", "", fmt.Errorf("parse git diff header: %w", err)
	}
	newPath, rest, err := readPathToken(rest)
	if err != nil {
		return "", "", fmt.Errorf("parse git diff header: %w", err)
	}
	if strings.TrimSpace(rest) != "" {
		return "", "", fmt.Errorf("unexpected text in git diff header %q", header)
	}
	return stripPrefix(oldPath), stripPrefix(newPath), nil
}

func readPathToken(input string) (string, string, error) {
	input = strings.TrimLeft(input, " ")
	if input == "" {
		return "", "", fmt.Errorf("missing path")
	}
	if input[0] == '"' {
		escaped := false
		for i := 1; i < len(input); i++ {
			if input[i] == '"' && !escaped {
				token, err := strconv.Unquote(input[:i+1])
				return token, input[i+1:], err
			}
			if input[i] == '\\' && !escaped {
				escaped = true
			} else {
				escaped = false
			}
		}
		return "", "", fmt.Errorf("unterminated quoted path")
	}
	end := strings.IndexByte(input, ' ')
	if end < 0 {
		return input, "", nil
	}
	return input[:end], input[end:], nil
}

func parseFileHeader(header string) (string, error) {
	path, _, err := readPathToken(header)
	if err != nil {
		return "", err
	}
	return stripPrefix(path), nil
}

func stripPrefix(path string) string {
	return strings.TrimPrefix(strings.TrimPrefix(path, "a/"), "b/")
}

func parseHunk(line string) (*hunk, error) {
	end := strings.Index(line[3:], " @@")
	if end < 0 {
		return nil, fmt.Errorf("missing closing @@")
	}
	ranges := strings.Fields(line[3 : 3+end])
	if len(ranges) != 2 {
		return nil, fmt.Errorf("expected old and new ranges")
	}
	oldStart, oldCount, err := parseRange(ranges[0], '-')
	if err != nil {
		return nil, err
	}
	newStart, newCount, err := parseRange(ranges[1], '+')
	if err != nil {
		return nil, err
	}
	return &hunk{
		oldLine: oldStart,
		newLine: newStart,
		oldLeft: oldCount,
		newLeft: newCount,
	}, nil
}

func parseRange(value string, prefix byte) (int, int, error) {
	if len(value) < 2 || value[0] != prefix {
		return 0, 0, fmt.Errorf("invalid range %q", value)
	}
	parts := strings.SplitN(value[1:], ",", 2)
	start, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid range start %q", value)
	}
	count := 1
	if len(parts) == 2 {
		count, err = strconv.Atoi(parts[1])
		if err != nil || count < 0 {
			return 0, 0, fmt.Errorf("invalid range count %q", value)
		}
	}
	return start, count, nil
}

func consumeHunkLine(file *File, active *hunk, line string) error {
	if line == "" {
		return fmt.Errorf("empty line inside hunk")
	}
	switch line[0] {
	case '\\':
		return nil
	case ' ':
		if active.oldLeft == 0 || active.newLeft == 0 {
			return fmt.Errorf("context line exceeds hunk range")
		}
		active.oldLine++
		active.newLine++
		active.oldLeft--
		active.newLeft--
	case '-':
		if active.oldLeft == 0 {
			return fmt.Errorf("deleted line exceeds hunk range")
		}
		file.Changes = append(file.Changes, Change{
			Kind:    DeletedChange,
			OldLine: active.oldLine,
			Text:    line[1:],
		})
		active.oldLine++
		active.oldLeft--
	case '+':
		if active.newLeft == 0 {
			return fmt.Errorf("added line exceeds hunk range")
		}
		file.Changes = append(file.Changes, Change{
			Kind:    AddedChange,
			NewLine: active.newLine,
			Text:    line[1:],
		})
		active.newLine++
		active.newLeft--
	default:
		return fmt.Errorf("unexpected line prefix %q", line[0])
	}
	return nil
}
