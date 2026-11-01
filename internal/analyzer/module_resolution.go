package analyzer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type importedSymbol struct {
	file   string
	symbol string
}

type pathAlias struct {
	pattern string
	targets []string
}

type moduleResolver struct {
	root    string
	baseURL string
	aliases []pathAlias
}

type tsconfig struct {
	CompilerOptions struct {
		BaseURL string              `json:"baseUrl"`
		Paths   map[string][]string `json:"paths"`
	} `json:"compilerOptions"`
}

func newModuleResolver(root string) (*moduleResolver, error) {
	resolver := &moduleResolver{root: root}
	configPath := filepath.Join(root, "tsconfig.json")
	raw, err := os.ReadFile(configPath)
	if os.IsNotExist(err) {
		return resolver, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read TypeScript config %s: %w", configPath, err)
	}
	var config tsconfig
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, fmt.Errorf("parse TypeScript config %s: %w", configPath, err)
	}
	resolver.baseURL = config.CompilerOptions.BaseURL
	for pattern, targets := range config.CompilerOptions.Paths {
		resolver.aliases = append(resolver.aliases, pathAlias{pattern: pattern, targets: targets})
	}
	sort.Slice(resolver.aliases, func(i, j int) bool {
		return len(resolver.aliases[i].pattern) > len(resolver.aliases[j].pattern)
	})
	return resolver, nil
}

func (resolver *moduleResolver) imports(file sourceFile) map[string]importedSymbol {
	imports := make(map[string]importedSymbol)
	tokens := file.tokens
	for i := 0; i < len(tokens); i++ {
		if tokens[i].text != "import" || i+1 >= len(tokens) || tokens[i+1].text == "(" {
			continue
		}
		from := i + 1
		for from < len(tokens) && tokens[from].text != "from" && tokens[from].text != ";" {
			from++
		}
		if from+1 >= len(tokens) || tokens[from].text != "from" || tokens[from+1].kind != stringToken {
			continue
		}
		targetFile, ok := resolver.resolve(file.path, tokens[from+1].text)
		if !ok {
			continue
		}
		for j := i + 1; j < from; j++ {
			if tokens[j].kind == identifierToken && tokens[j].text != "type" &&
				(j == i+1 || tokens[j-1].text == ",") {
				exported, local := "default", tokens[j].text
				resolvedFile, resolvedSymbol := resolver.followReexport(targetFile, exported, make(map[string]bool))
				imports[local] = importedSymbol{file: resolvedFile, symbol: resolvedSymbol}
			}
			if tokens[j].text != "{" {
				continue
			}
			close := matchingToken(tokens, j, "{", "}")
			if close < 0 || close > from {
				break
			}
			for _, specifier := range splitArguments(tokens, j+1, close) {
				if specifier[0] >= specifier[1] {
					continue
				}
				exported := tokens[specifier[0]].text
				local := exported
				if specifier[0]+2 < specifier[1] && tokens[specifier[0]+1].text == "as" {
					local = tokens[specifier[0]+2].text
				}
				if tokens[specifier[0]].kind == identifierToken &&
					(local != "" && tokens[specifier[0]].text != "type") {
					resolvedFile, resolvedSymbol := resolver.followReexport(targetFile, exported, make(map[string]bool))
					imports[local] = importedSymbol{file: resolvedFile, symbol: resolvedSymbol}
				}
			}
			break
		}
	}
	for i := 0; i+3 < len(tokens); i++ {
		if tokens[i].text != "require" || tokens[i+1].text != "(" ||
			tokens[i+2].kind != stringToken {
			continue
		}
		targetFile, ok := resolver.resolve(file.path, tokens[i+2].text)
		if !ok {
			continue
		}
		open := i - 1
		if open >= 0 && tokens[open].text == "=" {
			open--
		}
		if open < 0 || tokens[open].text != "}" {
			continue
		}
		for open >= 0 && tokens[open].text != "{" {
			open--
		}
		if open < 0 {
			continue
		}
		close := matchingToken(tokens, open, "{", "}")
		if close < 0 || close >= i {
			continue
		}
		for _, specifier := range splitArguments(tokens, open+1, close) {
			if specifier[0] >= specifier[1] {
				continue
			}
			exported, local := tokens[specifier[0]].text, tokens[specifier[0]].text
			for j := specifier[0] + 1; j+1 < specifier[1]; j++ {
				if tokens[j].text == ":" || tokens[j].text == "as" {
					local = tokens[j+1].text
					break
				}
			}
			resolvedFile, resolvedSymbol := resolver.followReexport(targetFile, exported, make(map[string]bool))
			imports[local] = importedSymbol{file: resolvedFile, symbol: resolvedSymbol}
		}
	}
	return imports
}

func (resolver *moduleResolver) dependencies(file sourceFile) []string {
	dependencies := make(map[string]bool)
	tokens := file.tokens
	for i := 0; i < len(tokens); i++ {
		if tokens[i].text == "import" || tokens[i].text == "export" {
			for j := i + 1; j+1 < len(tokens) && tokens[j].text != ";"; j++ {
				if tokens[j].text == "from" && tokens[j+1].kind == stringToken {
					if target, ok := resolver.resolve(file.path, tokens[j+1].text); ok {
						dependencies[target] = true
					}
					break
				}
				if tokens[j].line > tokens[i].line {
					break
				}
			}
		}
		if tokens[i].text == "require" && i+2 < len(tokens) && tokens[i+1].text == "(" &&
			tokens[i+2].kind == stringToken {
			if target, ok := resolver.resolve(file.path, tokens[i+2].text); ok {
				dependencies[target] = true
			}
		}
	}
	result := make([]string, 0, len(dependencies))
	for dependency := range dependencies {
		result = append(result, dependency)
	}
	sort.Strings(result)
	return result
}

func (resolver *moduleResolver) followReexport(file, symbol string, visited map[string]bool) (string, string) {
	key := file + "\x00" + symbol
	if visited[key] {
		return file, symbol
	}
	visited[key] = true
	raw, err := os.ReadFile(filepath.Join(resolver.root, filepath.FromSlash(file)))
	if err != nil {
		return file, symbol
	}
	tokens, err := lex(string(raw))
	if err != nil {
		return file, symbol
	}
	for i := 0; i+1 < len(tokens); i++ {
		if tokens[i].text != "export" {
			continue
		}
		if tokens[i+1].text == "default" {
			nameIndex := i + 2
			if nameIndex < len(tokens) && tokens[nameIndex].text == "function" {
				nameIndex++
			}
			if nameIndex < len(tokens) && tokens[nameIndex].kind == identifierToken {
				return file, tokens[nameIndex].text
			}
		}
		if tokens[i+1].text == "*" {
			from := i + 2
			for from < len(tokens) && tokens[from].text != "from" && tokens[from].text != ";" {
				from++
			}
			if from+1 < len(tokens) && tokens[from].text == "from" && tokens[from+1].kind == stringToken {
				if nextFile, ok := resolver.resolve(file, tokens[from+1].text); ok {
					return resolver.followReexport(nextFile, symbol, visited)
				}
			}
			continue
		}
		if tokens[i+1].text != "{" {
			continue
		}
		close := matchingToken(tokens, i+1, "{", "}")
		if close < 0 {
			continue
		}
		from := close + 1
		for from < len(tokens) && tokens[from].text != "from" && tokens[from].text != ";" {
			from++
		}
		if from >= len(tokens) || tokens[from].text != "from" {
			for _, specifier := range splitArguments(tokens, i+2, close) {
				if specifier[0] >= specifier[1] {
					continue
				}
				exported, publicName := tokens[specifier[0]].text, tokens[specifier[0]].text
				if specifier[0]+2 < specifier[1] && tokens[specifier[0]+1].text == "as" {
					publicName = tokens[specifier[0]+2].text
				}
				if publicName == symbol {
					return file, exported
				}
			}
			continue
		}
		if from+1 >= len(tokens) || tokens[from].text != "from" ||
			tokens[from+1].kind != stringToken {
			continue
		}
		for _, specifier := range splitArguments(tokens, i+2, close) {
			if specifier[0] >= specifier[1] {
				continue
			}
			exported := tokens[specifier[0]].text
			publicName := exported
			if specifier[0]+2 < specifier[1] && tokens[specifier[0]+1].text == "as" {
				publicName = tokens[specifier[0]+2].text
			}
			if publicName != symbol {
				continue
			}
			if nextFile, ok := resolver.resolve(file, tokens[from+1].text); ok {
				return resolver.followReexport(nextFile, exported, visited)
			}
		}
	}
	return file, symbol
}

func (resolver *moduleResolver) resolve(fromFile, specifier string) (string, bool) {
	candidates := make([]string, 0)
	if strings.HasPrefix(specifier, ".") {
		candidates = append(candidates, filepath.Join(filepath.Dir(fromFile), filepath.FromSlash(specifier)))
	} else {
		for _, alias := range resolver.aliases {
			if suffix, matched := matchPathPattern(alias.pattern, specifier); matched {
				for _, target := range alias.targets {
					target = strings.Replace(target, "*", suffix, 1)
					candidates = append(candidates, filepath.Join(resolver.baseURL, filepath.FromSlash(target)))
				}
				break
			}
		}
		if len(candidates) == 0 && resolver.baseURL != "" {
			candidates = append(candidates, filepath.Join(resolver.baseURL, filepath.FromSlash(specifier)))
		}
	}
	for _, candidate := range candidates {
		for _, resolved := range sourceCandidates(candidate) {
			absolute := filepath.Join(resolver.root, resolved)
			info, err := os.Stat(absolute)
			if err != nil || info.IsDir() {
				continue
			}
			relative, err := filepath.Rel(resolver.root, absolute)
			if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				return filepath.ToSlash(relative), true
			}
		}
	}
	return "", false
}

func matchPathPattern(pattern, value string) (string, bool) {
	pieces := strings.SplitN(pattern, "*", 2)
	if len(pieces) == 1 {
		return "", pattern == value
	}
	if !strings.HasPrefix(value, pieces[0]) || !strings.HasSuffix(value, pieces[1]) ||
		len(value) < len(pieces[0])+len(pieces[1]) {
		return "", false
	}
	return value[len(pieces[0]) : len(value)-len(pieces[1])], true
}

func sourceCandidates(path string) []string {
	extensions := []string{".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
	candidates := []string{path}
	ext := filepath.Ext(path)
	hasSourceExtension := false
		for _, extension := range extensions {
		if ext == extension {
			hasSourceExtension = true
			break
		}
	}
	if !hasSourceExtension {
		for _, extension := range extensions {
			candidates = append(candidates, path+extension)
		}
	} else {
		switch ext {
		case ".js":
			candidates = append(candidates, strings.TrimSuffix(path, ext)+".ts",
				strings.TrimSuffix(path, ext)+".tsx")
		case ".jsx":
			candidates = append(candidates, strings.TrimSuffix(path, ext)+".tsx")
		case ".mjs":
			candidates = append(candidates, strings.TrimSuffix(path, ext)+".mts")
		case ".cjs":
			candidates = append(candidates, strings.TrimSuffix(path, ext)+".cts")
	}
	}
	for _, extension := range extensions {
		candidates = append(candidates, filepath.Join(path, "index"+extension))
	}
	return candidates
}
