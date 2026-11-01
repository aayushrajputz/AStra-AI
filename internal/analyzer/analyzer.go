package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"unicode"

	"github.com/astra-ai/astra/internal/diff"
)

type Route struct {
	Method     string   `json:"method"`
	Path       string   `json:"path"`
	File       string   `json:"file"`
	Line       int      `json:"line"`
	Handlers   []string `json:"handlers,omitempty"`
	Confidence string   `json:"confidence"`
}

type Warning struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Message string `json:"message"`
}

type Report struct {
	Routes         []Route       `json:"routes"`
	AffectedRoutes []RouteImpact `json:"affected_routes,omitempty"`
	Warnings       []Warning     `json:"warnings,omitempty"`
}

type RouteImpact struct {
	Route      Route    `json:"route"`
	Chain      []string `json:"chain,omitempty"`
	Reason     string   `json:"reason"`
	Confidence string   `json:"confidence"`
	Severity   string   `json:"severity"`
}

type RouteExplanation struct {
	Route  Route      `json:"route"`
	Chains [][]string `json:"chains"`
}

type tokenKind uint8

const (
	identifierToken tokenKind = iota
	stringToken
	dynamicStringToken
	punctuationToken
)

type token struct {
	text   string
	kind   tokenKind
	line   int
	column int
	start  int
	end    int
}

type sourceFile struct {
	path    string
	tokens  []token
	imports map[string]importedSymbol
}

type functionInfo struct {
	name      string
	file      string
	startLine int
	endLine   int
	bodyStart int
	bodyEnd   int
	calls     []string
	imports   map[string]importedSymbol
}

type functionParameter struct {
	name     string
	typeName string
	optional bool
}

type functionSignature struct {
	name       string
	parameters []functionParameter
}

type signatureFinding struct {
	severity string
	reason   string
}

type mount struct {
	owner  string
	target string
	prefix string
}

var routeMethods = map[string]bool{
	"get": true, "post": true, "put": true, "patch": true,
	"delete": true, "options": true, "head": true, "all": true,
}

func Analyze(root string) (*Report, error) {
	files, err := loadFiles(root)
	if err != nil {
		return nil, err
	}
	report := analyzeFiles(files)
	return report, nil
}

func AnalyzeWithCache(root, cacheDir string) (*Report, error) {
	files, err := loadFilesWithCache(root, cacheDir)
	if err != nil {
		return nil, err
	}
	return analyzeFiles(files), nil
}

func AnalyzeDiff(root string, changes []diff.File) (*Report, error) {
	files, err := loadFiles(root)
	if err != nil {
		return nil, err
	}
	report := analyzeFiles(files)
	functions := indexFunctions(files)
	report.AffectedRoutes = affectedRoutes(report.Routes, changes, functions, importsByFile(files), files)
	return report, nil
}

func AnalyzeDiffWithCache(root string, changes []diff.File, cacheDir string) (*Report, error) {
	files, err := loadFilesWithCache(root, cacheDir)
	if err != nil {
		return nil, err
	}
	report := analyzeFiles(files)
	functions := indexFunctions(files)
	report.AffectedRoutes = affectedRoutes(report.Routes, changes, functions, importsByFile(files), files)
	return report, nil
}

func BlastRadius(root, file, symbol string, line int) ([]RouteImpact, error) {
	files, err := loadFiles(root)
	if err != nil {
		return nil, err
	}
	report := analyzeFiles(files)
	functions := indexFunctions(files)
	fileImports := importsByFile(files)

	targetNames := make(map[string]bool)
	for _, definitions := range functions {
		for _, definition := range definitions {
			if definition.file != file {
				continue
			}
			if symbol != "" && definition.name == symbol ||
				symbol == "" && line >= definition.startLine && line <= definition.endLine {
				targetNames[definition.name] = true
			}
		}
	}
	if len(targetNames) == 0 {
		return nil, fmt.Errorf("no function symbol found in %s for the requested symbol or line", file)
	}
	sortedTargets := make([]string, 0, len(targetNames))
	for target := range targetNames {
		sortedTargets = append(sortedTargets, target)
	}
	sort.Strings(sortedTargets)

	impacts := make([]RouteImpact, 0)
	for _, route := range report.Routes {
		for _, handler := range route.Handlers {
			for _, target := range sortedTargets {
				chain, ok := callChain(handler, route.File, target, file,
					fileImports[route.File], functions, make(map[string]bool))
				if !ok {
					continue
				}
				impacts = append(impacts, RouteImpact{
					Route: route, Chain: chain,
					Reason:     "symbol is reachable from a route handler",
					Confidence: route.Confidence, Severity: "potential",
				})
				break
			}
			if len(impacts) > 0 && routeKey(impacts[len(impacts)-1].Route) == routeKey(route) {
				break
			}
		}
	}
	return impacts, nil
}

func ExplainRoute(root, method, path string) (*RouteExplanation, error) {
	files, err := loadFiles(root)
	if err != nil {
		return nil, err
	}
	report := analyzeFiles(files)
	functions := indexFunctions(files)
	fileImports := importsByFile(files)
	for _, route := range report.Routes {
		if !strings.EqualFold(route.Method, method) || route.Path != path {
			continue
		}
		explanation := &RouteExplanation{Route: route, Chains: make([][]string, 0)}
		for _, handler := range route.Handlers {
			collectCallChains(handler, route.File, fileImports[route.File], functions,
				[]string{handler}, make(map[string]bool), &explanation.Chains)
		}
		if len(explanation.Chains) == 0 {
			for _, handler := range route.Handlers {
				explanation.Chains = append(explanation.Chains, []string{handler})
			}
		}
		return explanation, nil
	}
	return nil, fmt.Errorf("route %s %s was not found", strings.ToUpper(method), path)
}

func collectCallChains(current, currentFile string, imports map[string]importedSymbol,
	functions map[string][]functionInfo, chain []string, visited map[string]bool, results *[][]string) {
	visitKey := currentFile + "\x00" + current
	if visited[visitKey] {
		return
	}
	visited[visitKey] = true
	definitions := resolveFunction(current, currentFile, imports, functions)
	expanded := false
	for _, definition := range definitions {
		for _, called := range definition.calls {
			nextName, nextFile := called, definition.file
			if target, ok := definition.imports[called]; ok {
				nextName, nextFile = target.symbol, target.file
			}
			nextDefinitions := resolveFunction(nextName, nextFile, definition.imports, functions)
			if len(nextDefinitions) == 0 {
				continue
			}
			expanded = true
			nextChain := append(append([]string(nil), chain...), nextName)
			collectCallChains(nextName, nextFile, definition.imports, functions,
				nextChain, cloneVisited(visited), results)
		}
	}
	if !expanded && len(chain) > 0 {
		*results = append(*results, append([]string(nil), chain...))
	}
}

func cloneVisited(visited map[string]bool) map[string]bool {
	clone := make(map[string]bool, len(visited))
	for key, value := range visited {
		clone[key] = value
	}
	return clone
}

func loadFiles(root string) ([]sourceFile, error) {
	return loadFilesUsing(root, nil)
}

func loadFilesWithCache(root, cacheDir string) ([]sourceFile, error) {
	cache, err := openParseCache(cacheDir, root)
	if err != nil {
		return nil, err
	}
	files, err := loadFilesUsing(root, func(_ string, content []byte) ([]token, error) {
		tokens, err := cache.parse(content)
		if err != nil {
			return nil, err
		}
		return tokens, nil
	})
	if err != nil {
		return nil, err
	}
	if err := cache.flush(); err != nil {
		return nil, err
	}
	return files, nil
}

func loadFilesUsing(root string, parse func(string, []byte) ([]token, error)) ([]sourceFile, error) {
	resolver, err := newModuleResolver(root)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0)
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "node_modules", "vendor", "dist", "build":
				if path != root {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !isSourceFile(path) {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	files := make([]sourceFile, len(paths))
	errorsByFile := make([]error, len(paths))
	workers := min(8, len(paths))
	if workers > 0 {
		jobs := make(chan int)
		var wait sync.WaitGroup
		wait.Add(workers)
		for range workers {
			go func() {
				defer wait.Done()
				for index := range jobs {
					path := paths[index]
					content, err := os.ReadFile(path)
					if err != nil {
						errorsByFile[index] = fmt.Errorf("read %s: %w", path, err)
						continue
					}
					var tokens []token
					if parse == nil {
						tokens, err = lex(string(content))
					} else {
						tokens, err = parse(path, content)
					}
					if err != nil {
						errorsByFile[index] = fmt.Errorf("parse %s: %w", path, err)
						continue
					}
					relative, err := filepath.Rel(root, path)
					if err != nil {
						errorsByFile[index] = err
						continue
					}
					file := sourceFile{path: filepath.ToSlash(relative), tokens: tokens}
					file.imports = resolver.imports(file)
					files[index] = file
				}
			}()
		}
		for index := range paths {
			jobs <- index
		}
		close(jobs)
		wait.Wait()
	}
	for _, fileErr := range errorsByFile {
		if fileErr != nil {
			return nil, fileErr
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	return files, nil
}

func isSourceFile(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs":
		return true
	default:
		return false
	}
}

func analyzeFiles(files []sourceFile) *Report {
	report := &Report{
		Routes:   make([]Route, 0),
		Warnings: make([]Warning, 0),
	}
	mounts := make([]mount, 0)
	prefixes := make(map[string][]string)
	routeReceivers := make(map[string]string)

	for _, file := range files {
		tokens := file.tokens
		for i := 0; i+3 < len(tokens); i++ {
			if tokens[i].kind != identifierToken || tokens[i+1].text != "." ||
				tokens[i+2].kind != identifierToken || tokens[i+3].text != "(" {
				continue
			}
			receiver, method := tokens[i].text, tokens[i+2].text
			close := matchingToken(tokens, i+3, "(", ")")
			if close < 0 {
				continue
			}
			args := splitArguments(tokens, i+4, close)

			if method == "use" {
				prefix, target, ok := mountArguments(tokens, args)
				if ok {
					mounts = append(mounts, mount{owner: receiver, target: target, prefix: prefix})
				}
				continue
			}
			if method == "register" {
				prefix, plugin, ok := fastifyRegistration(tokens, args)
				if ok {
					if target, found := pluginReceiver(tokens, plugin); found {
						mounts = append(mounts, mount{owner: receiver, target: target, prefix: prefix})
					}
				}
				continue
			}

			if routeMethods[method] {
				if len(args) == 0 || args[0][0] >= args[0][1] || tokens[args[0][0]].kind != stringToken {
					report.Warnings = append(report.Warnings, Warning{
						File: file.path, Line: tokens[i].line,
						Message: "route path is dynamic or unsupported; route was not indexed",
					})
					continue
				}
				route := Route{
					Method:     strings.ToUpper(method),
					Path:       tokens[args[0][0]].text,
					File:       file.path,
					Line:       tokens[i].line,
					Confidence: "heuristic",
				}
				route.Handlers = handlerNames(tokens, args[1:])
				report.Routes = append(report.Routes, route)
				routeReceivers[routeKey(route)] = receiver
				continue
			}

			if method == "route" && len(args) > 0 && args[0][0] < args[0][1] &&
				tokens[args[0][0]].kind == stringToken {
				routes := expressRouteChain(file.path, tokens, receiver, tokens[args[0][0]].text, i, close)
				for _, route := range routes {
					report.Routes = append(report.Routes, route)
					routeReceivers[routeKey(route)] = receiver
				}
			}
		}
	}

	for _, m := range mounts {
		if _, exists := prefixes[m.owner]; !exists {
			prefixes[m.owner] = []string{""}
		}
	}
	for range mounts {
		changed := false
		for _, m := range mounts {
			basePrefixes := prefixes[m.owner]
			if len(basePrefixes) == 0 {
				basePrefixes = []string{""}
			}
			for _, base := range basePrefixes {
				combined := joinPath(base, m.prefix)
				if !contains(prefixes[m.target], combined) {
					prefixes[m.target] = append(prefixes[m.target], combined)
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}

	for i := range report.Routes {
		route := &report.Routes[i]
		receiver := routeReceivers[routeKey(*route)]
		for _, prefix := range prefixes[receiver] {
			if prefix != "" {
				route.Path = joinPath(prefix, route.Path)
				break
			}
		}
	}
	nestRoutes, _ := analyzeNestFiles(files)
	report.Routes = append(report.Routes, nestRoutes...)
	sort.Slice(report.Routes, func(i, j int) bool {
		a, b := report.Routes[i], report.Routes[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Method != b.Method {
			return a.Method < b.Method
		}
		return a.Path < b.Path
	})
	return report
}

func fastifyRegistration(tokens []token, args [][2]int) (string, string, bool) {
	if len(args) == 0 || args[0][1]-args[0][0] != 1 ||
		tokens[args[0][0]].kind != identifierToken {
		return "", "", false
	}
	plugin := tokens[args[0][0]].text
	prefix := ""
	for _, arg := range args[1:] {
		for i := arg[0]; i+2 < arg[1]; i++ {
			if tokens[i].text == "prefix" && tokens[i+1].text == ":" &&
				tokens[i+2].kind == stringToken {
				prefix = tokens[i+2].text
				return prefix, plugin, true
			}
		}
	}
	return "", "", false
}

func pluginReceiver(tokens []token, plugin string) (string, bool) {
	for i := 0; i+2 < len(tokens); i++ {
		if tokens[i].text != "function" || tokens[i+1].text != plugin ||
			tokens[i+2].text != "(" {
			continue
		}
		close := matchingToken(tokens, i+2, "(", ")")
		if close <= i+3 || tokens[i+3].kind != identifierToken {
			return "", false
		}
		return tokens[i+3].text, true
	}
	return "", false
}

func expressRouteChain(file string, tokens []token, receiver, path string, routeIndex, routeClose int) []Route {
	routes := make([]Route, 0)
	for i := routeClose + 1; i+3 < len(tokens); {
		if tokens[i].text != "." || tokens[i+1].kind != identifierToken ||
			!routeMethods[tokens[i+1].text] || tokens[i+2].text != "(" {
			break
		}
		methodClose := matchingToken(tokens, i+2, "(", ")")
		if methodClose < 0 {
			break
		}
		args := splitArguments(tokens, i+3, methodClose)
		route := Route{
			Method: strings.ToUpper(tokens[i+1].text), Path: path,
			File: file, Line: tokens[routeIndex].line, Confidence: "heuristic",
		}
		route.Handlers = handlerNames(tokens, args)
		routes = append(routes, route)
		i = methodClose + 1
	}
	return routes
}

func indexFunctions(files []sourceFile) map[string][]functionInfo {
	functions := make(map[string][]functionInfo)
	for _, file := range files {
		local := make([]functionInfo, 0)
		for i := 0; i < len(file.tokens); i++ {
			if file.tokens[i].text == "function" {
				nameIndex := i + 1
				if nameIndex < len(file.tokens) && file.tokens[nameIndex].text == "*" {
					nameIndex++
				}
				if nameIndex >= len(file.tokens) || file.tokens[nameIndex].kind != identifierToken {
					continue
				}
				openParen := nameIndex + 1
				for openParen < len(file.tokens) && file.tokens[openParen].text != "(" &&
					file.tokens[openParen].text != "{" && file.tokens[openParen].text != ";" {
					openParen++
				}
				if openParen >= len(file.tokens) || file.tokens[openParen].text != "(" {
					continue
				}
				closeParen := matchingToken(file.tokens, openParen, "(", ")")
				if closeParen < 0 {
					continue
				}
				bodyStart := closeParen + 1
				for bodyStart < len(file.tokens) && file.tokens[bodyStart].text != "{" &&
					file.tokens[bodyStart].text != ";" {
					bodyStart++
				}
				if bodyStart >= len(file.tokens) || file.tokens[bodyStart].text != "{" {
					continue
				}
				bodyEnd := matchingToken(file.tokens, bodyStart, "{", "}")
				if bodyEnd < 0 {
					continue
				}
				local = append(local, functionInfo{
					name: file.tokens[nameIndex].text, file: file.path,
					startLine: file.tokens[i].line, endLine: file.tokens[bodyEnd].line,
					bodyStart: bodyStart + 1, bodyEnd: bodyEnd, imports: file.imports,
				})
				continue
			}
			if file.tokens[i].text != "=>" {
				continue
			}
			nameIndex, equalIndex, ok := arrowName(file.tokens, i)
			if !ok {
				continue
			}
			bodyStart := i + 1
			if bodyStart >= len(file.tokens) || file.tokens[bodyStart].text != "{" {
				continue
			}
			bodyEnd := matchingToken(file.tokens, bodyStart, "{", "}")
			if bodyEnd < 0 {
				continue
			}
			local = append(local, functionInfo{
				name: file.tokens[nameIndex].text, file: file.path,
				startLine: file.tokens[equalIndex-1].line, endLine: file.tokens[bodyEnd].line,
				bodyStart: bodyStart + 1, bodyEnd: bodyEnd, imports: file.imports,
			})
		}
		for i := range local {
			called := make(map[string]bool)
			for j := local[i].bodyStart; j+1 < local[i].bodyEnd; j++ {
				if file.tokens[j].kind == identifierToken && file.tokens[j+1].text == "(" &&
					!isControlWord(file.tokens[j].text) {
					called[file.tokens[j].text] = true
				}
			}
			for name := range called {
				local[i].calls = append(local[i].calls, name)
			}
			sort.Strings(local[i].calls)
			functions[local[i].name] = append(functions[local[i].name], local[i])
		}
	}
	_, nestFunctions := analyzeNestFiles(files)
	for name, definitions := range nestFunctions {
		functions[name] = append(functions[name], definitions...)
	}
	return functions
}

func arrowName(tokens []token, arrow int) (int, int, bool) {
	for i := arrow - 1; i >= 1 && arrow-i <= 12; i-- {
		if tokens[i].text == "=" && tokens[i-1].kind == identifierToken {
			return i - 1, i, true
		}
		if tokens[i].text == ";" || tokens[i].text == "{" || tokens[i].text == "}" {
			break
		}
	}
	return 0, 0, false
}

func isControlWord(name string) bool {
	switch name {
	case "if", "for", "while", "switch", "catch", "function", "return", "new", "typeof":
		return true
	default:
		return false
	}
}

func importsByFile(files []sourceFile) map[string]map[string]importedSymbol {
	imports := make(map[string]map[string]importedSymbol, len(files))
	for _, file := range files {
		imports[file.path] = file.imports
	}
	return imports
}

func affectedRoutes(routes []Route, changes []diff.File, functions map[string][]functionInfo,
	fileImports map[string]map[string]importedSymbol, files []sourceFile) []RouteImpact {
	impacts := make([]RouteImpact, 0)
	added := make(map[string]bool)
	schemas := indexContractSchemas(files)
	routeContracts := indexRouteContracts(routes, files, schemas)
	for _, fileChange := range changes {
		if isCosmetic(fileChange) {
			continue
		}
		contractResult := routeContractChanges(routes, routeContracts, schemas, fileChange)
		for _, finding := range contractResult.findings {
			impacts = append(impacts, RouteImpact{
				Route: finding.route, Chain: append([]string(nil), finding.route.Handlers...),
				Reason: finding.reason, Confidence: "heuristic",
				Severity: finding.severity,
			})
			added[routeKey(finding.route)] = true
		}
		changedNames := make(map[string]bool)
		removedNames := make(map[string]bool)
		signatureFindings := make(map[string]signatureFinding)
		oldSignatures := make(map[string]functionSignature)
		newSignatures := make(map[string]functionSignature)
		directRoutes := make(map[int]bool)
		moduleLevel := fileChange.Status == diff.Deleted
		for changeIndex, change := range fileChange.Changes {
			if contractResult.handledChanges[changeIndex] {
				continue
			}
			if signature, ok := parseFunctionSignature(change.Text); ok {
				if change.Kind == diff.DeletedChange {
					oldSignatures[signature.name] = signature
				} else {
					newSignatures[signature.name] = signature
				}
			}
			if change.Kind == diff.AddedChange {
				matched := false
				for name, definitions := range functions {
					for _, definition := range definitions {
						if definition.file == fileChange.Path && change.NewLine >= definition.startLine &&
							change.NewLine <= definition.endLine {
							changedNames[name] = true
							matched = true
						}
					}
				}
				for _, route := range routes {
					if route.File == fileChange.Path && route.Line == change.NewLine {
						directRoutes[route.Line] = true
						matched = true
					}
				}
				if !matched {
					moduleLevel = true
				}
			} else {
				matched := false
				if name, ok := changedFunctionName(change.Text); ok {
					changedNames[name] = true
					if !hasFunction(functions[name], fileChange.Path) {
						removedNames[name] = true
					}
					matched = true
				}
				if !matched {
					for name, definitions := range functions {
						for _, definition := range definitions {
							if definition.file == fileChange.Path && change.OldLine >= definition.startLine-1 &&
								change.OldLine <= definition.endLine+1 {
								changedNames[name] = true
								matched = true
							}
						}
					}
				}
				if route, ok := changedRoute(change.Text, fileChange.Path, change.OldLine); ok {
					impacts = append(impacts, RouteImpact{
						Route: route, Reason: "route declaration was removed",
						Confidence: "heuristic", Severity: "breaking",
					})
					added[routeKey(route)] = true
					matched = true
				}
				if !matched {
					moduleLevel = true
				}
			}
		}
		for name, oldSignature := range oldSignatures {
			if newSignature, ok := newSignatures[name]; ok {
				if finding, changed := compareSignatures(oldSignature, newSignature); changed {
					signatureFindings[name] = finding
					changedNames[name] = true
				}
			}
		}

		sortedChangedNames := make([]string, 0, len(changedNames))
		for name := range changedNames {
			sortedChangedNames = append(sortedChangedNames, name)
		}
		sort.Strings(sortedChangedNames)

		for _, route := range routes {
			if moduleLevel {
				key := routeKey(route)
				if !added[key] {
					impacts = append(impacts, RouteImpact{
						Route: route, Reason: "change could not be assigned to a function; all routes are flagged",
						Confidence: "uncertain", Severity: "uncertain",
					})
					added[key] = true
				}
			}
			if directRoutes[route.Line] && route.File == fileChange.Path && !added[routeKey(route)] {
				impacts = append(impacts, RouteImpact{
					Route: route, Reason: "route declaration was added or changed",
					Confidence: "heuristic", Severity: "non-breaking",
				})
				added[routeKey(route)] = true
			}
		}

		for _, route := range routes {
			if added[routeKey(route)] {
				continue
			}
			for _, handler := range route.Handlers {
				for _, changedName := range sortedChangedNames {
					chain, ok := callChain(handler, route.File, changedName, fileChange.Path,
						fileImports[route.File], functions, make(map[string]bool))
					if !ok {
						continue
					}
					impacts = append(impacts, RouteImpact{
						Route: route, Chain: chain,
						Reason:     "changed function is reachable from a route handler",
						Confidence: route.Confidence, Severity: "potential",
					})
					if finding, ok := signatureFindings[changedName]; ok {
						impacts[len(impacts)-1].Reason = finding.reason
						impacts[len(impacts)-1].Severity = finding.severity
					} else if removedNames[changedName] {
						impacts[len(impacts)-1].Reason = "route depends on a removed function"
						impacts[len(impacts)-1].Severity = "breaking"
					} else if oldSignatures[changedName].name != "" && newSignatures[changedName].name != "" {
						impacts[len(impacts)-1].Reason = "function signature changed without a detected breaking parameter change"
						impacts[len(impacts)-1].Severity = "non-breaking"
					}
					added[routeKey(route)] = true
					break
				}
				if added[routeKey(route)] {
					break
				}
			}
		}
	}
	sort.Slice(impacts, func(i, j int) bool {
		a, b := impacts[i].Route, impacts[j].Route
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Path < b.Path
	})
	return impacts
}

func parseFunctionSignature(source string) (functionSignature, bool) {
	tokens, err := lex(source)
	if err != nil {
		return functionSignature{}, false
	}
	nameIndex, openParen := -1, -1
	for i := 0; i+1 < len(tokens); i++ {
		if tokens[i].text == "function" && tokens[i+1].kind == identifierToken {
			nameIndex = i + 1
			for j := nameIndex + 1; j < len(tokens); j++ {
				if tokens[j].text == "(" {
					openParen = j
					break
				}
			}
			break
		}
	}
	if nameIndex < 0 {
		for i, candidate := range tokens {
			if candidate.text != "=>" {
				continue
			}
			var ok bool
			nameIndex, _, ok = arrowName(tokens, i)
			if !ok {
				continue
			}
			for j := i - 1; j >= 0; j-- {
				if tokens[j].text == "(" {
					openParen = j
					break
				}
				if tokens[j].text == "=" || tokens[j].text == ";" {
					break
				}
			}
			if openParen >= 0 {
				break
			}
		}
	}
	if nameIndex < 0 || openParen < 0 {
		return functionSignature{}, false
	}
	closeParen := matchingToken(tokens, openParen, "(", ")")
	if closeParen < 0 {
		return functionSignature{}, false
	}
	arguments := splitArguments(tokens, openParen+1, closeParen)
	parameters := make([]functionParameter, 0, len(arguments))
	for _, argument := range arguments {
		if argument[0] >= argument[1] {
			continue
		}
		parameter := functionParameter{}
		for i := argument[0]; i < argument[1]; i++ {
			if tokens[i].kind == identifierToken {
				parameter.name = tokens[i].text
				break
			}
		}
		if parameter.name == "" {
			continue
		}
		typeStart, typeEnd := -1, argument[1]
		for i := argument[0]; i < argument[1]; i++ {
			switch tokens[i].text {
			case "?":
				parameter.optional = true
			case "=":
				parameter.optional = true
				typeEnd = i
			case ":":
				typeStart = i + 1
			}
		}
		if typeStart >= 0 && typeStart < typeEnd {
			for i := typeStart; i < typeEnd; i++ {
				parameter.typeName += tokens[i].text
			}
		}
		parameters = append(parameters, parameter)
	}
	return functionSignature{name: tokens[nameIndex].text, parameters: parameters}, true
}

func compareSignatures(oldSignature, newSignature functionSignature) (signatureFinding, bool) {
	oldParameters := make(map[string]functionParameter, len(oldSignature.parameters))
	newParameters := make(map[string]functionParameter, len(newSignature.parameters))
	for _, parameter := range oldSignature.parameters {
		oldParameters[parameter.name] = parameter
	}
	for _, parameter := range newSignature.parameters {
		newParameters[parameter.name] = parameter
	}
	for _, oldParameter := range oldSignature.parameters {
		newParameter, exists := newParameters[oldParameter.name]
		if !exists {
			return signatureFinding{
				severity: "breaking",
				reason:   fmt.Sprintf("required route dependency parameter %q was removed", oldParameter.name),
			}, true
		}
		if oldParameter.typeName != "" && newParameter.typeName != "" &&
			oldParameter.typeName != newParameter.typeName {
			return signatureFinding{
				severity: "breaking",
				reason: fmt.Sprintf("parameter %q changed type from %s to %s",
					oldParameter.name, oldParameter.typeName, newParameter.typeName),
			}, true
		}
	}
	for _, newParameter := range newSignature.parameters {
		if _, exists := oldParameters[newParameter.name]; !exists && !newParameter.optional {
			return signatureFinding{
				severity: "breaking",
				reason:   fmt.Sprintf("required parameter %q was added", newParameter.name),
			}, true
		}
	}
	return signatureFinding{
		severity: "non-breaking",
		reason:   "function signature changed without a detected breaking parameter change",
	}, true
}

func isCosmetic(file diff.File) bool {
	oldTokens, newTokens := make([]token, 0), make([]token, 0)
	for _, change := range file.Changes {
		tokens, err := lex(change.Text)
		if err != nil {
			return false
		}
		switch change.Kind {
		case diff.DeletedChange:
			oldTokens = append(oldTokens, tokens...)
		case diff.AddedChange:
			newTokens = append(newTokens, tokens...)
		}
	}
	if len(oldTokens) != len(newTokens) {
		return false
	}
	for i := range oldTokens {
		if oldTokens[i].kind != newTokens[i].kind || oldTokens[i].text != newTokens[i].text {
			return false
		}
	}
	return true
}

func hasFunction(definitions []functionInfo, file string) bool {
	for _, definition := range definitions {
		if definition.file == file {
			return true
		}
	}
	return false
}

func changedRoute(source, file string, line int) (Route, bool) {
	tokens, err := lex(source)
	if err != nil {
		return Route{}, false
	}
	for i := 0; i+4 < len(tokens); i++ {
		if tokens[i].kind != identifierToken || tokens[i+1].text != "." ||
			!routeMethods[tokens[i+2].text] || tokens[i+3].text != "(" {
			continue
		}
		close := matchingToken(tokens, i+3, "(", ")")
		if close < 0 {
			continue
		}
		args := splitArguments(tokens, i+4, close)
		if len(args) == 0 || args[0][0] >= args[0][1] || tokens[args[0][0]].kind != stringToken {
			continue
		}
		return Route{
			Method: strings.ToUpper(tokens[i+2].text), Path: tokens[args[0][0]].text,
			File: file, Line: line, Handlers: handlerNames(tokens, args[1:]),
			Confidence: "heuristic",
		}, true
	}
	return Route{}, false
}

func changedFunctionName(source string) (string, bool) {
	tokens, err := lex(source)
	if err != nil {
		return "", false
	}
	if len(tokens) >= 2 && tokens[0].text == "function" && tokens[1].kind == identifierToken {
		return tokens[1].text, true
	}
	if len(tokens) >= 2 && (tokens[0].text == "const" || tokens[0].text == "let" ||
		tokens[0].text == "var") && tokens[1].kind == identifierToken {
		for _, candidate := range tokens[2:] {
			if candidate.text == "=>" {
				return tokens[1].text, true
			}
		}
	}
	return "", false
}

func callChain(current, currentFile, target, targetFile string, imports map[string]importedSymbol,
	functions map[string][]functionInfo, visited map[string]bool) ([]string, bool) {
	definitions := resolveFunction(current, currentFile, imports, functions)
	if current == target {
		if currentFile == targetFile {
			return []string{current}, true
		}
		for _, definition := range definitions {
			if definition.file == targetFile {
				return []string{current}, true
			}
		}
	}
	visitKey := currentFile + "\x00" + current
	if visited[visitKey] {
		return nil, false
	}
	visited[visitKey] = true
	for _, definition := range definitions {
		for _, called := range definition.calls {
			nextName, nextFile := called, definition.file
			if targetImport, ok := definition.imports[called]; ok {
				nextName, nextFile = targetImport.symbol, targetImport.file
			}
			if chain, ok := callChain(nextName, nextFile, target, targetFile,
				definition.imports, functions, visited); ok {
				return append([]string{current}, chain...), true
			}
		}
	}
	return nil, false
}

func resolveFunction(name, fromFile string, imports map[string]importedSymbol,
	functions map[string][]functionInfo) []functionInfo {
	if imported, ok := imports[name]; ok {
		matches := make([]functionInfo, 0)
		for _, definition := range functions[imported.symbol] {
			if definition.file == imported.file {
				matches = append(matches, definition)
			}
		}
		return matches
	}
	local := make([]functionInfo, 0)
	for _, definition := range functions[name] {
		if definition.file == fromFile {
			local = append(local, definition)
		}
	}
	if len(local) > 0 {
		return local
	}
	return functions[name]
}

func routeKey(route Route) string {
	return route.Method + "\x00" + route.Path + "\x00" + route.File + "\x00" + fmt.Sprint(route.Line)
}

func mountArguments(tokens []token, args [][2]int) (string, string, bool) {
	if len(args) == 0 || args[0][0] >= args[0][1] {
		return "", "", false
	}
	prefix := ""
	targetArg := 0
	if tokens[args[0][0]].kind == stringToken {
		prefix = tokens[args[0][0]].text
		targetArg = 1
	}
	if targetArg >= len(args) || args[targetArg][0] >= args[targetArg][1] {
		return "", "", false
	}
	for i := args[targetArg][0]; i < args[targetArg][1]; i++ {
		if tokens[i].kind == identifierToken {
			return prefix, tokens[i].text, true
		}
	}
	return "", "", false
}

func handlerNames(tokens []token, args [][2]int) []string {
	names := make([]string, 0)
	seen := make(map[string]bool)
	for _, arg := range args {
		if arg[0] >= arg[1] || tokens[arg[0]].kind != identifierToken {
			continue
		}
		name := tokens[arg[0]].text
		simpleReference := true
		for i := arg[0] + 1; i < arg[1]; i += 2 {
			if i+1 >= arg[1] || tokens[i].text != "." || tokens[i+1].kind != identifierToken {
				simpleReference = false
				break
			}
			name = tokens[i+1].text
		}
		if simpleReference && !seen[name] {
			names = append(names, name)
			seen[name] = true
		}
	}
	return names
}

func splitArguments(tokens []token, start, end int) [][2]int {
	args := make([][2]int, 0)
	begin, depth := start, 0
	for i := start; i < end; i++ {
		if tokens[i].kind != punctuationToken {
			continue
		}
		switch tokens[i].text {
		case "(", "[", "{":
			depth++
		case ")", "]", "}":
			depth--
		case ",":
			if depth == 0 {
				args = append(args, [2]int{begin, i})
				begin = i + 1
			}
		}
	}
	if begin < end {
		args = append(args, [2]int{begin, end})
	}
	return args
}

func matchingToken(tokens []token, start int, open, close string) int {
	depth := 0
	for i := start; i < len(tokens); i++ {
		if tokens[i].kind != punctuationToken {
			continue
		}
		switch tokens[i].text {
		case open:
			depth++
		case close:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func joinPath(prefix, route string) string {
	if prefix == "" || prefix == "/" {
		if route == "" {
			return "/"
		}
		return "/" + strings.TrimLeft(route, "/")
	}
	if route == "" || route == "/" {
		return "/" + strings.Trim(prefix, "/")
	}
	return "/" + strings.Trim(prefix, "/") + "/" + strings.TrimLeft(route, "/")
}

func contains(values []string, value string) bool {
	for _, existing := range values {
		if existing == value {
			return true
		}
	}
	return false
}

func lex(source string) ([]token, error) {
	tokens := make([]token, 0)
	line := 1
	lineStart := 0
	for i := 0; i < len(source); {
		r := rune(source[i])
		if unicode.IsSpace(r) {
			if source[i] == '\n' {
				line++
				lineStart = i + 1
			}
			i++
			continue
		}
		if i+1 < len(source) && source[i:i+2] == "//" {
			for i < len(source) && source[i] != '\n' {
				i++
			}
			continue
		}
		if i+1 < len(source) && source[i:i+2] == "/*" {
			startLine := line
			i += 2
			for i+1 < len(source) && source[i:i+2] != "*/" {
				if source[i] == '\n' {
					line++
					lineStart = i + 1
				}
				i++
			}
			if i+1 >= len(source) {
				return nil, fmt.Errorf("unterminated block comment starting on line %d", startLine)
			}
			i += 2
			continue
		}
		start, tokenLine := i, line
		tokenColumn := start - lineStart
		switch source[i] {
		case '\'', '"', '`':
			quote := source[i]
			isTemplate := quote == '`'
			i++
			var value strings.Builder
			closed := false
			dynamic := false
			for i < len(source) {
				ch := source[i]
				if ch == '\\' && i+1 < len(source) {
					value.WriteByte(source[i+1])
					i += 2
					continue
				}
				if ch == quote {
					i++
					closed = true
					break
				}
				if isTemplate && ch == '$' && i+1 < len(source) && source[i+1] == '{' {
					dynamic = true
				}
				if ch == '\n' {
					line++
					lineStart = i + 1
				}
				value.WriteByte(ch)
				i++
			}
			if !closed {
				return nil, fmt.Errorf("unterminated string starting on line %d", tokenLine)
			}
			kind := stringToken
			if dynamic {
				kind = dynamicStringToken
			}
			tokens = append(tokens, token{text: value.String(), kind: kind, line: tokenLine,
				column: tokenColumn, start: start, end: i})
		default:
			if isIdentifierStart(source[i]) {
				i++
				for i < len(source) && isIdentifierPart(source[i]) {
					i++
				}
				tokens = append(tokens, token{text: source[start:i], kind: identifierToken, line: tokenLine,
					column: tokenColumn, start: start, end: i})
				continue
			}
			text := source[i : i+1]
			i++
			if i < len(source) && ((text == "=" && source[i] == '>') ||
				(text == "?" && source[i] == '.') ||
				(text == "." && source[i] == '.')) {
				text += source[i : i+1]
				i++
				if text == ".." && i < len(source) && source[i] == '.' {
					text += source[i : i+1]
					i++
				}
			}
			tokens = append(tokens, token{text: text, kind: punctuationToken, line: tokenLine,
				column: tokenColumn, start: start, end: i})
		}
	}
	return tokens, nil
}

func isIdentifierStart(ch byte) bool {
	return ch == '_' || ch == '$' || ch >= 0x80 || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z'
}

func isIdentifierPart(ch byte) bool {
	return isIdentifierStart(ch) || ch >= '0' && ch <= '9'
}
