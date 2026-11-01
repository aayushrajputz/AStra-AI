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
	Method      string   `json:"method"`
	Path        string   `json:"path"`
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Handlers    []string `json:"handlers,omitempty"`
	Middlewares []string `json:"middlewares,omitempty"`
	DepSymbols  []string `json:"dep_symbols,omitempty"`
	Confidence  string   `json:"confidence"`
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
	Route      Route      `json:"route"`
	Chain      []string   `json:"chain,omitempty"`
	Reason     string     `json:"reason"`
	Confidence string     `json:"confidence"`
	Severity   string     `json:"severity"`
	Resolution string     `json:"resolution,omitempty"`
	Symbol     string     `json:"symbol,omitempty"`
	CallSites  []CallSite `json:"call_sites,omitempty"`
}

type CallSite struct {
	Caller        string `json:"caller"`
	Callee        string `json:"callee"`
	File          string `json:"file"`
	Line          int    `json:"line"`
	ArgumentCount int    `json:"argument_count"`
	HasSpread     bool   `json:"has_spread,omitempty"`
	HasNamedArgs  bool   `json:"has_named_args,omitempty"`
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
	modules []string
	goFile  *goSourceFile
}

type functionInfo struct {
	name      string
	file      string
	startLine int
	endLine   int
	bodyStart int
	bodyEnd   int
	calls     []string
	callSites []CallSite
	imports   map[string]importedSymbol
}

type topLevelSymbol struct {
	id        string
	file      string
	name      string
	kind      string
	startLine int
	endLine   int
	start     int
	end       int
	exported  bool
	hash      string
}

type functionParameter struct {
	name     string
	typeName string
	optional bool
	variadic bool
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
	return analyzeDiffFiles(files, changes), nil
}

func DebugDiff(root string, changes []diff.File) ([]string, error) {
	files, err := loadFiles(root)
	if err != nil {
		return nil, err
	}
	symbols := indexTopLevelSymbols(files)
	report := analyzeFiles(files)
	var lines []string
	for _, fileChange := range changes {
		for _, change := range fileChange.Changes {
			line, kind := change.NewLine, "added"
			if change.Kind == diff.DeletedChange {
				line, kind = change.OldLine, "deleted"
			}
			var attributed []string
			for _, symbol := range symbols {
				if symbol.file == fileChange.Path && line >= symbol.startLine && line <= symbol.endLine {
					attributed = append(attributed, fmt.Sprintf("%s (%s:%d-%d)",
						symbol.name, symbol.kind, symbol.startLine, symbol.endLine))
				}
			}
			if len(attributed) == 0 {
				attributed = append(attributed, "none")
			}
			sort.Strings(attributed)
			lines = append(lines, fmt.Sprintf("debug: changed range %s:%d (%s), attributed to %s",
				fileChange.Path, line, kind, strings.Join(attributed, ", ")))
		}
	}
	foundLoginSchema := false
	for _, symbol := range symbols {
		if symbol.name == "loginSchema" {
			foundLoginSchema = true
			lines = append(lines, fmt.Sprintf("debug: loginSchema symbol: kind=%s file=%s lines=%d-%d",
				symbol.kind, symbol.file, symbol.startLine, symbol.endLine))
		}
	}
	if !foundLoginSchema {
		lines = append(lines, "debug: loginSchema symbol: not found")
	}
	fileByPath := make(map[string]sourceFile, len(files))
	for _, file := range files {
		fileByPath[file.path] = file
	}
	foundLoginRoute := false
	for _, route := range report.Routes {
		if !strings.EqualFold(route.Method, "POST") || route.Path != "/login" {
			continue
		}
		foundLoginRoute = true
		file := fileByPath[route.File]
		args := routeArguments(file, route)
		calls := make([]string, 0)
		identifiers := make(map[string]bool)
		for _, arg := range args {
			calls = append(calls, tokenText(file.tokens, arg[0], arg[1]))
			for i := arg[0]; i < arg[1]; i++ {
				if file.tokens[i].kind == identifierToken {
					identifiers[file.tokens[i].text] = true
				}
			}
		}
		lines = append(lines, fmt.Sprintf("debug: POST /login route args/calls: %s; identifiers include loginSchema=%t",
			strings.Join(calls, " | "), identifiers["loginSchema"]))
		locals := make([]string, 0, len(file.imports))
		for local := range file.imports {
			locals = append(locals, local)
		}
		sort.Strings(locals)
		for _, local := range locals {
			imported := file.imports[local]
			if local == "loginSchema" || imported.symbol == "loginSchema" {
				lines = append(lines, fmt.Sprintf("debug: loginSchema import: %s -> %s#%s",
					local, imported.file, imported.symbol))
			}
		}
		lines = append(lines, fmt.Sprintf("debug: POST /login route middleware=%v dependency symbols=%v",
			route.Middlewares, route.DepSymbols))
	}
	if !foundLoginRoute {
		lines = append(lines, "debug: POST /login route: not found")
	}
	return lines, nil
}

func routeArguments(file sourceFile, route Route) [][2]int {
	for i := 0; i+3 < len(file.tokens); i++ {
		if file.tokens[i].line != route.Line || file.tokens[i].kind != identifierToken ||
			file.tokens[i+1].text != "." ||
			!strings.EqualFold(file.tokens[i+2].text, route.Method) ||
			file.tokens[i+3].text != "(" {
			continue
		}
		close := matchingToken(file.tokens, i+3, "(", ")")
		if close >= 0 {
			return splitArguments(file.tokens, i+4, close)
		}
	}
	return nil
}

func AnalyzeDiffWithCache(root string, changes []diff.File, cacheDir string) (*Report, error) {
	files, err := loadFilesWithCache(root, cacheDir)
	if err != nil {
		return nil, err
	}
	return analyzeDiffFiles(files, changes), nil
}

func AnalyzeDiffWithContent(root, cacheDir string, changes []diff.File,
	overrides map[string][]byte, excluded map[string]bool) (*Report, error) {
	cache, err := openParseCache(cacheDir, root)
	if err != nil {
		return nil, err
	}
	files, err := loadFilesUsingContent(root, func(_ string, content []byte) ([]token, error) {
		return cache.parse(content)
	}, overrides, excluded)
	if err != nil {
		return nil, err
	}
	if err := cache.flush(); err != nil {
		return nil, err
	}
	return analyzeDiffFiles(files, changes), nil
}

func analyzeDiffFiles(files []sourceFile, changes []diff.File) *Report {
	report := analyzeFiles(files)
	functions := indexFunctions(files)
	impacts, warnings := affectedRoutes(report.Routes, changes, functions, importsByFile(files), files)
	report.AffectedRoutes = impacts
	report.Warnings = append(report.Warnings, warnings...)
	return report
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
	return loadFilesUsingContent(root, parse, nil, nil)
}

func loadFilesUsingContent(root string, parse func(string, []byte) ([]token, error),
	overrides map[string][]byte, excluded map[string]bool) ([]sourceFile, error) {
	resolver, err := newModuleResolver(root)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0)
	if overrides != nil {
		for relative := range overrides {
			if excluded[relative] || !isSourceFile(relative) {
				continue
			}
			paths = append(paths, filepath.Join(root, filepath.FromSlash(relative)))
		}
	} else {
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
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			if excluded[filepath.ToSlash(relative)] {
				return nil
			}
			paths = append(paths, path)
			return nil
		})
		if err != nil {
			return nil, err
		}
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
					relative, err := filepath.Rel(root, path)
					if err != nil {
						errorsByFile[index] = err
						continue
					}
					content, overridden := overrides[filepath.ToSlash(relative)]
					if !overridden {
						content, err = os.ReadFile(path)
						if err != nil {
							errorsByFile[index] = fmt.Errorf("read %s: %w", path, err)
							continue
						}
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
					file := sourceFile{path: filepath.ToSlash(relative), tokens: tokens}
					file.imports = resolver.imports(file)
					file.modules = resolver.dependencies(file)
					if strings.EqualFold(filepath.Ext(path), ".go") {
						file.goFile, err = parseGoSource(path, content)
						if err != nil {
							errorsByFile[index] = fmt.Errorf("parse %s: %w", path, err)
							continue
						}
					}
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
	linkGoImports(root, files)
	return files, nil
}

func isSourceFile(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go":
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
				if len(args) < 2 || args[0][0] >= args[0][1] {
					continue
				}
				if tokens[args[0][0]].kind != stringToken {
					if !isRouteCallCandidate(receiver, tokens, args) {
						continue
					}
					report.Warnings = append(report.Warnings, Warning{
						File: file.path, Line: tokens[i].line,
						Message: "route path is dynamic or unsupported; route was not indexed",
					})
					continue
				}
				if !isRouteCallCandidate(receiver, tokens, args) {
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
	goRoutes, _ := analyzeGoFiles(files)
	report.Routes = append(report.Routes, goRoutes...)
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
	annotateRouteDependencies(report.Routes, files)
	return report
}

func annotateRouteDependencies(routes []Route, files []sourceFile) {
	symbols := indexTopLevelSymbols(files)
	byName := make(map[string]map[string]bool)
	fileByPath := make(map[string]sourceFile, len(files))
	for _, symbol := range symbols {
		if byName[symbol.file] == nil {
			byName[symbol.file] = make(map[string]bool)
		}
		byName[symbol.file][symbol.name] = true
	}
	for _, file := range files {
		fileByPath[file.path] = file
	}
	for routeIndex := range routes {
		route := &routes[routeIndex]
		file, ok := fileByPath[route.File]
		if !ok {
			continue
		}
		for i := 0; i+3 < len(file.tokens); i++ {
			if file.tokens[i].line != route.Line || file.tokens[i].kind != identifierToken ||
				file.tokens[i+1].text != "." ||
				!strings.EqualFold(file.tokens[i+2].text, route.Method) ||
				file.tokens[i+3].text != "(" {
				continue
			}
			close := matchingToken(file.tokens, i+3, "(", ")")
			if close < 0 {
				break
			}
			args := splitArguments(file.tokens, i+4, close)
			for _, arg := range args[1:] {
				if arg[0] >= arg[1] {
					continue
				}
				for tokenIndex := arg[0]; tokenIndex < arg[1]; tokenIndex++ {
					if file.tokens[tokenIndex].kind != identifierToken {
						continue
					}
					name := file.tokens[tokenIndex].text
					if tokenIndex+1 < arg[1] && file.tokens[tokenIndex+1].text == "(" {
						middleware := name
						if imported, exists := file.imports[name]; exists && imported.symbol != "" {
							middleware = imported.symbol
						}
						if !contains(route.Middlewares, middleware) {
							route.Middlewares = append(route.Middlewares, middleware)
						}
					}
					if symbolID, exists := resolveSymbolID(file.path, name, byName, file.imports, symbols); exists {
						if !contains(route.DepSymbols, symbolID) {
							route.DepSymbols = append(route.DepSymbols, symbolID)
						}
					}
				}
			}
			break
		}
		sort.Strings(route.Middlewares)
		sort.Strings(route.DepSymbols)
	}
}

func isRouteCallCandidate(receiver string, tokens []token, args [][2]int) bool {
	name := strings.ToLower(receiver)
	switch {
	case name == "redis", name == "cache", name == "map", strings.Contains(name, "redis"),
		strings.Contains(name, "cache"), strings.Contains(name, "map"), name == "req",
		name == "request", strings.Contains(name, "client"), name == "db",
		name == "database", name == "http", name == "axios":
		return false
	}
	switch name {
	case "router", "app", "server", "api", "group", "v1", "v2", "r", "fastify":
		return true
	}
	if strings.HasSuffix(name, "router") || strings.HasSuffix(name, "routes") {
		return true
	}
	for _, arg := range args[1:] {
		if looksLikeRouteHandler(tokens, arg) {
			return true
		}
	}
	return false
}

func looksLikeRouteHandler(tokens []token, arg [2]int) bool {
	if arg[0] >= arg[1] {
		return false
	}
	first := arg[0]
	if tokens[first].text == "async" {
		first++
	}
	if first >= arg[1] {
		return false
	}
	if tokens[first].text == "function" || tokens[first].text == "(" {
		return true
	}
	for index := first; index < arg[1]; index++ {
		if tokens[index].text == "=>" {
			return true
		}
	}
	if tokens[first].kind != identifierToken {
		return false
	}
	name := strings.ToLower(tokens[first].text)
	if strings.Contains(name, "handler") || strings.Contains(name, "middleware") ||
		strings.Contains(name, "controller") || strings.HasSuffix(name, "callback") {
		return true
	}
	for index := 0; index+2 < len(tokens); index++ {
		if tokens[index].text != "function" {
			continue
		}
		functionName := index + 1
		if tokens[functionName].text == "*" {
			functionName++
		}
		if functionName >= len(tokens) || tokens[functionName].text != tokens[first].text ||
			functionName+1 >= len(tokens) || tokens[functionName+1].text != "(" {
			continue
		}
		close := matchingToken(tokens, functionName+1, "(", ")")
		if close < 0 {
			continue
		}
		params := splitArguments(tokens, functionName+2, close)
		if len(params) >= 2 && isRequestParameter(tokens, params[0]) &&
			isResponseParameter(tokens, params[1]) {
			return true
		}
	}
	return false
}

func isRequestParameter(tokens []token, param [2]int) bool {
	if param[0] >= param[1] || tokens[param[0]].kind != identifierToken {
		return false
	}
	name := strings.ToLower(tokens[param[0]].text)
	return name == "req" || name == "request"
}

func isResponseParameter(tokens []token, param [2]int) bool {
	if param[0] >= param[1] || tokens[param[0]].kind != identifierToken {
		return false
	}
	name := strings.ToLower(tokens[param[0]].text)
	return name == "res" || name == "response"
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
		if file.goFile != nil {
			continue
		}
		local := make([]functionInfo, 0)
		for i := 0; i < len(file.tokens); i++ {
			if file.tokens[i].text == "function" {
				nameIndex := i + 1
				if nameIndex < len(file.tokens) && file.tokens[nameIndex].text == "*" {
					nameIndex++
				}
				if nameIndex >= len(file.tokens) {
					continue
				}
				startLine := file.tokens[i].line
				if variableIndex, ok := variableDeclarationNameBefore(file.tokens, i); ok {
					nameIndex = variableIndex
					startLine = file.tokens[variableIndex].line
				} else if file.tokens[nameIndex].text == "(" ||
					file.tokens[nameIndex].kind != identifierToken {
					continue
				}
				openParen := i + 1
				if openParen < len(file.tokens) && file.tokens[openParen].text == "*" {
					openParen++
				}
				if openParen < len(file.tokens) && file.tokens[openParen].kind == identifierToken {
					openParen++
				}
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
					startLine: startLine, endLine: file.tokens[bodyEnd].line,
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
					callee := file.tokens[j].text
					called[callee] = true
					close := matchingToken(file.tokens, j+1, "(", ")")
					if close > j+1 && close <= local[i].bodyEnd {
						arguments := splitArguments(file.tokens, j+2, close)
						site := CallSite{
							Caller: local[i].name, Callee: callee, File: file.path,
							Line: file.tokens[j].line, ArgumentCount: len(arguments),
						}
						for _, argument := range arguments {
							for tokenIndex := argument[0]; tokenIndex < argument[1]; tokenIndex++ {
								switch file.tokens[tokenIndex].text {
								case "...":
									site.HasSpread = true
								case ":":
									site.HasNamedArgs = true
								}
							}
						}
						local[i].callSites = append(local[i].callSites, site)
					}
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
	_, goFunctions := analyzeGoFiles(files)
	for name, definitions := range goFunctions {
		functions[name] = append(functions[name], definitions...)
	}
	return functions
}

func indexTopLevelSymbols(files []sourceFile) map[string]topLevelSymbol {
	symbols := make(map[string]topLevelSymbol)
	for _, file := range files {
		depth := 0
		for i := 0; i < len(file.tokens); i++ {
			if depth != 0 {
				if file.tokens[i].text == "{" {
					depth++
				} else if file.tokens[i].text == "}" {
					depth--
				}
				continue
			}
			tokenIndex, exported := i, i > 0 && file.tokens[i-1].text == "export"
			switch file.tokens[i].text {
			case "export":
				continue
			case "const", "let", "var":
				if i+1 >= len(file.tokens) || file.tokens[i+1].kind != identifierToken {
					continue
				}
				nameIndex := i + 1
				end := declarationEnd(file.tokens, i)
				if end < nameIndex {
					continue
				}
				if declarationValueIsFunction(file.tokens, nameIndex, end) {
					i = end
					continue
				}
				addTopLevelSymbol(symbols, file, nameIndex, tokenIndex, end, "const", exported)
				i = end
				continue
			case "type", "interface", "enum":
				if i+1 >= len(file.tokens) || file.tokens[i+1].kind != identifierToken {
					continue
				}
				end := declarationEnd(file.tokens, i)
				kind := "type"
				if file.tokens[i].text == "enum" {
					kind = "enum"
				}
				addTopLevelSymbol(symbols, file, i+1, tokenIndex, end, kind, exported)
				i = end
				continue
			}
			if file.tokens[i].text == "{" {
				depth++
			}
		}
	}
	return symbols
}

func addTopLevelSymbol(symbols map[string]topLevelSymbol, file sourceFile, nameIndex, start, end int,
	kind string, exported bool) {
	if nameIndex < 0 || nameIndex >= len(file.tokens) || end < start || end >= len(file.tokens) {
		return
	}
	name := file.tokens[nameIndex].text
	id := file.path + "\x00" + name
	symbols[id] = topLevelSymbol{
		id: id, file: file.path, name: name, kind: kind,
		startLine: file.tokens[start].line, endLine: file.tokens[end].line,
		start: start, end: end, exported: exported, hash: hashTokens(file.tokens, start, end+1),
	}
}

func declarationEnd(tokens []token, start int) int {
	paren, bracket, brace := 0, 0, 0
	for i := start + 1; i < len(tokens); i++ {
		if paren == 0 && bracket == 0 && brace == 0 && i > start+1 &&
			tokens[i].line > tokens[i-1].line &&
			(tokens[i].text == "export" || tokens[i].text == "const" || tokens[i].text == "let" ||
				tokens[i].text == "var" || tokens[i].text == "type" ||
				tokens[i].text == "interface" || tokens[i].text == "enum" ||
				tokens[i].text == "function" || tokens[i].text == "import") {
			return i - 1
		}
		switch tokens[i].text {
		case "(":
			paren++
		case ")":
			paren--
		case "[":
			bracket++
		case "]":
			bracket--
		case "{":
			brace++
		case "}":
			if brace == 0 {
				return i - 1
			}
			brace--
		case ";":
			if paren == 0 && bracket == 0 && brace == 0 {
				return i
			}
		}
	}
	return len(tokens) - 1
}

func declarationValueIsFunction(tokens []token, nameIndex, end int) bool {
	equal := nameIndex + 1
	for equal <= end && tokens[equal].text != "=" {
		equal++
	}
	if equal > end || equal+1 > end {
		return false
	}
	if tokens[equal+1].text == "function" || tokens[equal+1].text == "async" &&
		equal+2 <= end && tokens[equal+2].text == "function" {
		return true
	}
	paren, bracket, brace := 0, 0, 0
	for i := equal + 1; i <= end; i++ {
		switch tokens[i].text {
		case "(":
			paren++
		case ")":
			paren--
		case "[":
			bracket++
		case "]":
			bracket--
		case "{":
			brace++
		case "}":
			brace--
		case "=>":
			if paren == 0 && bracket == 0 && brace == 0 {
				return true
			}
		case ",":
			if paren == 0 && bracket == 0 && brace == 0 {
				return false
			}
		}
	}
	return false
}

func indexSymbolReferences(files []sourceFile, symbols map[string]topLevelSymbol) (map[string]map[string]bool, map[string]map[string]bool, map[string]map[string]bool) {
	graphConsumers := make(map[string]map[string]bool)
	graphUses := make(map[string]map[string]bool)
	graphUsedBy := make(map[string]map[string]bool)
	byName := make(map[string]map[string]bool)
	for _, symbol := range symbols {
		if byName[symbol.file] == nil {
			byName[symbol.file] = make(map[string]bool)
		}
		byName[symbol.file][symbol.name] = true
	}
	for _, file := range files {
		for i := 0; i < len(file.tokens); i++ {
			if file.tokens[i].text != "function" && file.tokens[i].text != "const" && file.tokens[i].text != "let" &&
				file.tokens[i].text != "var" && file.tokens[i].text != "=>" {
				continue
			}
			name, start, end, ok := functionRangeForFile(file, i)
			if !ok {
				continue
			}
			for j := i; j < start; j++ {
				if j == i || file.tokens[j-1].text != ":" ||
					file.tokens[j].kind != identifierToken {
					continue
				}
				if symbolID, ok := resolveSymbolID(file.path, file.tokens[j].text, byName, file.imports, symbols); ok {
					addGraphEdge(graphConsumers, symbolID, "function:"+name)
					addGraphEdge(graphUses, symbolID, "function:"+name)
					addGraphEdge(graphUsedBy, "function:"+name, symbolID)
				}
			}
			for j := start; j < end; j++ {
				if file.tokens[j].kind != identifierToken {
					continue
				}
				candidate := file.tokens[j].text
				if candidate == "" || isControlWord(candidate) || candidate == name {
					continue
				}
				if symbolIsShadowed(file, j, candidate) {
					continue
				}
				if symbolID, ok := resolveSymbolID(file.path, candidate, byName, file.imports, symbols); ok {
					addGraphEdge(graphConsumers, symbolID, "function:"+name)
					addGraphEdge(graphUses, symbolID, "function:"+name)
					addGraphEdge(graphUsedBy, "function:"+name, symbolID)
				}
			}
		}
		for _, symbol := range symbols {
			if symbol.file != file.path {
				continue
			}
			for tokenIndex := symbol.start; tokenIndex <= symbol.end && tokenIndex < len(file.tokens); tokenIndex++ {
				if file.tokens[tokenIndex].kind != identifierToken || file.tokens[tokenIndex].text == symbol.name {
					continue
				}
				dependency, ok := resolveSymbolID(file.path, file.tokens[tokenIndex].text,
					byName, file.imports, symbols)
				if !ok || dependency == symbol.id {
					continue
				}
				addGraphEdge(graphConsumers, dependency, "symbol:"+symbol.id)
				addGraphEdge(graphUses, dependency, "symbol:"+symbol.id)
				addGraphEdge(graphUsedBy, "symbol:"+symbol.id, dependency)
			}
		}
	}
	return graphConsumers, graphUses, graphUsedBy
}

func symbolIsShadowed(file sourceFile, index int, name string) bool {
	for scope := 0; scope < len(file.tokens); scope++ {
		if file.tokens[scope].text != "function" && file.tokens[scope].text != "const" &&
			file.tokens[scope].text != "let" && file.tokens[scope].text != "var" &&
			file.tokens[scope].text != "=>" {
			continue
		}
		_, start, end, ok := functionRangeForFile(file, scope)
		if !ok || index < start || index >= end {
			continue
		}
		if functionHasParameter(file.tokens, scope, start, name) {
			return true
		}
		for i := start; i+1 < end; i++ {
			if (file.tokens[i].text == "const" || file.tokens[i].text == "let" ||
				file.tokens[i].text == "var" || file.tokens[i].text == "class") &&
				file.tokens[i+1].text == name {
				return true
			}
		}
	}
	return false
}

func functionHasParameter(tokens []token, functionIndex, bodyStart int, name string) bool {
	for close := bodyStart - 2; close > functionIndex; close-- {
		if tokens[close].text == ")" {
			open := close
			depth := 1
			for open > functionIndex+1 {
				open--
				if tokens[open].text == ")" {
					depth++
				} else if tokens[open].text == "(" {
					depth--
					if depth == 0 {
						break
					}
				}
			}
			if depth != 0 {
				return false
			}
			for _, parameter := range splitArguments(tokens, open+1, close) {
				for i := parameter[0]; i < parameter[1]; i++ {
					if tokens[i].kind == identifierToken && tokens[i].text == name {
						return true
					}
					if tokens[i].text == ":" || tokens[i].text == "=" {
						break
					}
				}
			}
			return false
		}
		if tokens[close].text == "{" || tokens[close].text == ";" {
			break
		}
	}
	return false
}

func resolveSymbolID(filePath, name string, byName map[string]map[string]bool,
	imports map[string]importedSymbol, symbols map[string]topLevelSymbol) (string, bool) {
	if byName[filePath] != nil && byName[filePath][name] {
		return filePath + "\x00" + name, true
	}
	if imported, ok := imports[name]; ok {
		if imported.file != "" && imported.symbol != "" {
			return imported.file + "\x00" + imported.symbol, true
		}
	}
	for id, symbol := range symbols {
		if symbol.name == name && symbol.file == filePath {
			return id, true
		}
	}
	return "", false
}

func addGraphEdge(edges map[string]map[string]bool, from, to string) {
	if edges[from] == nil {
		edges[from] = make(map[string]bool)
	}
	edges[from][to] = true
}

func routesImportingFile(routes []Route, files []sourceFile, target string) []Route {
	dependencies := make(map[string][]string, len(files))
	for _, file := range files {
		dependencies[file.path] = append(dependencies[file.path], file.modules...)
		for _, imported := range file.imports {
			if imported.file != "" {
				dependencies[file.path] = append(dependencies[file.path], imported.file)
			}
		}
	}
	result := make([]Route, 0)
	for _, route := range routes {
		if route.File == target {
			result = append(result, route)
			continue
		}
		visited := make(map[string]bool)
		queue := []string{route.File}
		found := false
		for len(queue) > 0 && !found {
			current := queue[0]
			queue = queue[1:]
			if visited[current] {
				continue
			}
			visited[current] = true
			for _, dependency := range dependencies[current] {
				if dependency == target {
					found = true
					break
				}
				queue = append(queue, dependency)
			}
		}
		if found {
			result = append(result, route)
		}
	}
	return result
}

func functionRangeForFile(file sourceFile, index int) (string, int, int, bool) {
	if file.tokens[index].text == "function" {
		if index+1 >= len(file.tokens) || file.tokens[index+1].kind != identifierToken {
			return "", 0, 0, false
		}
		name := file.tokens[index+1].text
		bodyStart := index + 2
		for bodyStart < len(file.tokens) && file.tokens[bodyStart].text != "{" {
			bodyStart++
		}
		if bodyStart >= len(file.tokens) {
			return "", 0, 0, false
		}
		bodyEnd := matchingToken(file.tokens, bodyStart, "{", "}")
		if bodyEnd < 0 {
			return "", 0, 0, false
		}
		return name, bodyStart + 1, bodyEnd, true
	}
	if file.tokens[index].text == "const" || file.tokens[index].text == "let" || file.tokens[index].text == "var" {
		if index+1 >= len(file.tokens) || file.tokens[index+1].kind != identifierToken {
			return "", 0, 0, false
		}
		name := file.tokens[index+1].text
		bodyStart := index + 2
		for bodyStart < len(file.tokens) && file.tokens[bodyStart].text != "=" && file.tokens[bodyStart].text != ";" {
			bodyStart++
		}
		if bodyStart >= len(file.tokens) || file.tokens[bodyStart].text != "=" {
			return "", 0, 0, false
		}
		bodyEnd := bodyStart + 1
		for bodyEnd < len(file.tokens) && file.tokens[bodyEnd].text != ";" && file.tokens[bodyEnd].text != "}" {
			bodyEnd++
		}
		if bodyEnd >= len(file.tokens) {
			return "", 0, 0, false
		}
		return name, bodyStart + 1, bodyEnd, true
	}
	return "", 0, 0, false
}

func declarationLooksLikeFunction(tokens []token, start int) bool {
	for i := start; i < len(tokens); i++ {
		if tokens[i].text == ";" || tokens[i].text == "}" {
			return false
		}
		if tokens[i].text == "=>" || tokens[i].text == "function" {
			return true
		}
	}
	return false
}

func hashTokens(tokens []token, start, end int) string {
	var builder strings.Builder
	for i := start; i < end && i < len(tokens); i++ {
		builder.WriteString(tokens[i].text)
	}
	return builder.String()
}

func changedTopLevelSymbols(fileChange diff.File, symbols map[string]topLevelSymbol) []string {
	matches := make([]string, 0)
	for id, symbol := range symbols {
		if symbol.file != fileChange.Path {
			continue
		}
		if fileChange.Status == diff.Deleted && symbol.startLine >= 1 {
			matches = append(matches, id)
			continue
		}
		for _, change := range fileChange.Changes {
			if change.Kind == diff.DeletedChange {
				if change.OldLine >= symbol.startLine && change.OldLine <= symbol.endLine {
					matches = append(matches, id)
					break
				}
			}
			if change.Kind == diff.AddedChange {
				if change.NewLine >= symbol.startLine && change.NewLine <= symbol.endLine {
					matches = append(matches, id)
					break
				}
			}
		}
	}
	return matches
}

func findRoutesForTopLevelSymbol(symbolID string, routes []Route, files []sourceFile,
	symbols map[string]topLevelSymbol, symbolConsumers map[string]map[string]bool,
	symbolUses map[string]map[string]bool, symbolUsedBy map[string]map[string]bool) []RouteImpact {
	current := []string{symbolID}
	seen := make(map[string]bool)
	functions := make(map[string]bool)
	for len(current) > 0 {
		id := current[0]
		current = current[1:]
		if seen[id] {
			continue
		}
		seen[id] = true
		for consumer := range symbolConsumers[id] {
			if strings.HasPrefix(consumer, "symbol:") {
				current = append(current, strings.TrimPrefix(consumer, "symbol:"))
			} else {
				functions[consumer] = true
			}
		}
		for dep := range symbolUses[id] {
			current = append(current, dep)
		}
		for dep := range symbolUsedBy[id] {
			current = append(current, dep)
		}
	}
	impacts := make([]RouteImpact, 0)
	for _, route := range routes {
		dependsOnSymbol := false
		for _, dependency := range route.DepSymbols {
			if seen[dependency] {
				dependsOnSymbol = true
				break
			}
		}
		for _, handler := range route.Handlers {
			consumerKey := "function:" + handler
			if dependsOnSymbol || handler == symbols[symbolID].name || functions[consumerKey] {
				chain := []string{symbols[symbolID].name}
				if len(route.Middlewares) > 0 {
					chain = append(chain, route.Middlewares[0])
				} else if handler != symbols[symbolID].name {
					chain = append(chain, handler)
				}
				chain = append(chain, route.Method+" "+route.Path)
				confidence, severity := "exact", "potential"
				reason := "top-level symbol changed and is used by a route dependency"
				if symbols[symbolID].kind == "type" || symbols[symbolID].kind == "enum" {
					confidence, severity = "uncertain", "uncertain"
					reason = "changed type contract could not be fully resolved"
				} else if topLevelSymbolIsZodSchema(symbols[symbolID], files) &&
					!routeUsesValidationMiddleware(route) {
					confidence, severity = "heuristic", "body-changed"
					reason = "schema direction unknown - review"
				}
				impacts = append(impacts, RouteImpact{
					Route:      route,
					Chain:      chain,
					Reason:     reason,
					Confidence: confidence,
					Severity:   severity,
					Symbol:     symbols[symbolID].name,
				})
				break
			}
		}
	}
	return impacts
}

func topLevelSymbolIsZodSchema(symbol topLevelSymbol, files []sourceFile) bool {
	for _, file := range files {
		if file.path != symbol.file {
			continue
		}
		for i := symbol.start; i+2 <= symbol.end && i+2 < len(file.tokens); i++ {
			if file.tokens[i].text == "z" && file.tokens[i+1].text == "." &&
				file.tokens[i+2].text == "object" {
				return true
			}
		}
	}
	return false
}

func arrowName(tokens []token, arrow int) (int, int, bool) {
	parenDepth, bracketDepth, braceDepth := 0, 0, 0
	for i := arrow - 1; i >= 0; i-- {
		switch tokens[i].text {
		case ")":
			parenDepth++
		case "(":
			if parenDepth > 0 {
				parenDepth--
			}
		case "]":
			bracketDepth++
		case "[":
			if bracketDepth > 0 {
				bracketDepth--
			}
		case "}":
			if parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 {
				return 0, 0, false
			}
			braceDepth++
		case "{":
			if braceDepth > 0 {
				braceDepth--
			} else if parenDepth == 0 && bracketDepth == 0 {
				return 0, 0, false
			}
		case "=":
			if parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 {
				if nameIndex, ok := variableDeclarationNameBefore(tokens, i); ok {
					return nameIndex, i, true
				}
				if i > 0 && tokens[i-1].kind == identifierToken {
					return i - 1, i, true
				}
			}
		case ";":
			if parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 {
				return 0, 0, false
			}
		}
	}
	return 0, 0, false
}

func variableDeclarationNameBefore(tokens []token, before int) (int, bool) {
	parenDepth, bracketDepth, braceDepth := 0, 0, 0
	for index := before - 1; index >= 0; index-- {
		switch tokenText := tokens[index].text; tokenText {
		case ")":
			parenDepth++
		case "(":
			if parenDepth > 0 {
				parenDepth--
			}
		case "]":
			bracketDepth++
		case "[":
			if bracketDepth > 0 {
				bracketDepth--
			}
		case "}":
			braceDepth++
		case "{":
			if braceDepth > 0 {
				braceDepth--
			}
		case ",":
			if parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 {
				return variableNameAfter(tokens, index+1, before)
			}
		case ";":
			if parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 {
				return 0, false
			}
		case "const", "let", "var":
			if parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 {
				return variableNameAfter(tokens, index+1, before)
			}
		case "function":
			if parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 {
				return 0, false
			}
		}
	}
	return 0, false
}

func variableNameAfter(tokens []token, start, end int) (int, bool) {
	for index := start; index < end; index++ {
		if tokens[index].kind == identifierToken {
			return index, true
		}
		if tokens[index].text == "=" || tokens[index].text == "," {
			return 0, false
		}
	}
	return 0, false
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
	fileImports map[string]map[string]importedSymbol, files []sourceFile) ([]RouteImpact, []Warning) {
	impacts := make([]RouteImpact, 0)
	warnings := make([]Warning, 0)
	added := make(map[string]bool)
	schemas := indexContractSchemas(files)
	routeContracts := indexRouteContracts(routes, files, schemas)
	symbols := indexTopLevelSymbols(files)
	symbolConsumers, symbolUses, symbolUsedBy := indexSymbolReferences(files, symbols)
	for _, fileChange := range changes {
		if !isSourceFile(fileChange.Path) {
			continue
		}
		if isCosmetic(fileChange) {
			continue
		}
		contractResult := routeContractChanges(routes, routeContracts, schemas, fileChange)
		for _, finding := range contractResult.findings {
			var chain []string
			for _, dependency := range finding.route.DepSymbols {
				file, name, ok := splitSchemaKey(dependency)
				if ok && file == fileChange.Path {
					chain = append(chain, name)
					break
				}
			}
			chain = append(chain, finding.route.Middlewares...)
			chain = append(chain, finding.route.Method+" "+finding.route.Path)
			confidence := "exact"
			if strings.Contains(finding.reason, "constraint tightened") ||
				strings.Contains(finding.reason, "schema logic changed") {
				confidence = "heuristic"
			}
			impacts = append(impacts, RouteImpact{
				Route: finding.route, Chain: chain,
				Reason: finding.reason, Confidence: confidence,
				Severity: finding.severity,
			})
			added[routeKey(finding.route)] = true
		}
		changedSymbols := changedTopLevelSymbols(fileChange, symbols)
		if len(changedSymbols) > 0 {
			for _, symbolID := range changedSymbols {
				for _, impact := range findRoutesForTopLevelSymbol(symbolID, routes, files, symbols, symbolConsumers, symbolUses, symbolUsedBy) {
					if !added[routeKey(impact.Route)] {
						impacts = append(impacts, impact)
						added[routeKey(impact.Route)] = true
					}
				}
			}
		}
		symbolChangedLines := make(map[int]bool)
		for changeIndex, change := range fileChange.Changes {
			line := change.NewLine
			if change.Kind == diff.DeletedChange {
				line = change.OldLine
			}
			for _, symbolID := range changedSymbols {
				symbol := symbols[symbolID]
				if line >= symbol.startLine && line <= symbol.endLine {
					symbolChangedLines[changeIndex] = true
					break
				}
			}
		}
		changedNames := make(map[string]bool)
		removedNames := make(map[string]bool)
		signatureFindings := make(map[string]signatureFinding)
		oldSignatures := make(map[string]functionSignature)
		newSignatures := make(map[string]functionSignature)
		directRoutes := make(map[int]bool)
		untracedChanges := make([]diff.Change, 0)
		if fileChange.Status == diff.Deleted && len(fileChange.Changes) == 0 {
			untracedChanges = append(untracedChanges, diff.Change{Kind: diff.DeletedChange, OldLine: 1})
		}
		for changeIndex, change := range fileChange.Changes {
			if contractResult.handledChanges[changeIndex] {
				continue
			}
			if symbolChangedLines[changeIndex] {
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
					untracedChanges = append(untracedChanges, change)
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
						Confidence: "exact", Severity: "breaking", Resolution: "unresolved",
						Symbol: route.Method + " " + route.Path,
					})
					added[routeKey(route)] = true
					matched = true
				}
				if !matched {
					untracedChanges = append(untracedChanges, change)
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
		sort.Slice(sortedChangedNames, func(i, j int) bool {
			priority := func(name string) int {
				if finding, ok := signatureFindings[name]; ok && finding.severity == "breaking" {
					return 2
				}
				if removedNames[name] {
					return 2
				}
				return 0
			}
			leftPriority, rightPriority := priority(sortedChangedNames[i]), priority(sortedChangedNames[j])
			if leftPriority != rightPriority {
				return leftPriority > rightPriority
			}
			return sortedChangedNames[i] < sortedChangedNames[j]
		})

		for _, change := range untracedChanges {
			line := change.NewLine
			if change.Kind == diff.DeletedChange {
				line = change.OldLine
			}
			warnings = append(warnings, Warning{
				File: fileChange.Path, Line: line, Message: "change could not be traced",
			})
		}
		for _, route := range routesImportingFile(routes, files, fileChange.Path) {
			key := routeKey(route)
			if len(untracedChanges) > 0 && !added[key] {
				impacts = append(impacts, RouteImpact{
					Route: route, Reason: "unattributed module-level change in an imported file",
					Confidence: "uncertain", Severity: "uncertain",
				})
				added[key] = true
			}
		}
		for _, route := range routes {
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
					if !ok && changedName == handler &&
						removedNames[changedName] && route.File == fileChange.Path {
						chain, ok = []string{handler}, true
					}
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
						if finding.severity == "breaking" {
							impact := &impacts[len(impacts)-1]
							impact.Symbol = changedName
							impact.CallSites, impact.Resolution = signatureCallSites(
								changedName, newSignatures[changedName], functions, route, chain,
							)
						}
					} else if removedNames[changedName] {
						impacts[len(impacts)-1].Reason = "route depends on a removed function"
						impacts[len(impacts)-1].Severity = "breaking"
						impacts[len(impacts)-1].Resolution = "unresolved"
						impacts[len(impacts)-1].Confidence = "exact"
						impacts[len(impacts)-1].Symbol = changedName
						impacts[len(impacts)-1].CallSites = callSitesFor(changedName, functions)
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
	return impacts, warnings
}

func signatureCallSites(name string, signature functionSignature,
	functions map[string][]functionInfo, route Route, chain []string) ([]CallSite, string) {
	sites := callSitesFor(name, functions)
	if len(sites) == 0 && len(chain) > 0 && chain[len(chain)-1] == name {
		for _, handler := range route.Handlers {
			if handler == name {
				sites = append(sites, CallSite{
					Caller: "HTTP client", Callee: name, File: route.File,
					Line: route.Line, ArgumentCount: 0,
				})
				break
			}
		}
	}
	if len(sites) == 0 {
		return nil, "resolved"
	}
	required := 0
	for _, parameter := range signature.parameters {
		if !parameter.optional && !parameter.variadic {
			required++
		}
	}
	maximum := len(signature.parameters)
	for _, parameter := range signature.parameters {
		if parameter.variadic {
			maximum = int(^uint(0) >> 1)
			break
		}
	}
	incompatible := make([]CallSite, 0)
	for _, site := range sites {
		if site.HasSpread || site.HasNamedArgs ||
			site.ArgumentCount < required || site.ArgumentCount > maximum {
			incompatible = append(incompatible, site)
		}
	}
	if len(incompatible) > 0 {
		return incompatible, "unresolved"
	}
	return nil, "resolved"
}

func callSitesFor(name string, functions map[string][]functionInfo) []CallSite {
	sites := make([]CallSite, 0)
	for _, definitions := range functions {
		for _, definition := range definitions {
			for _, site := range definition.callSites {
				matches := site.Callee == name
				if imported, ok := definition.imports[site.Callee]; ok && imported.symbol == name {
					matches = true
				}
				if matches {
					sites = append(sites, site)
				}
			}
		}
	}
	return sites
}

func parseFunctionSignature(source string) (functionSignature, bool) {
	tokens, err := lex(source)
	if err != nil {
		return functionSignature{}, false
	}
	if len(tokens) > 0 && tokens[0].text == "func" {
		return parseGoFunctionSignature(source)
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
			parenDepth := 0
			for j := i - 1; j >= 0; j-- {
				switch tokens[j].text {
				case ")":
					parenDepth++
				case "(":
					if parenDepth > 0 {
						parenDepth--
					}
					if parenDepth == 0 {
						openParen = j
					}
				case ";":
					break
				}
				if openParen >= 0 || tokens[j].text == ";" {
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
			if tokens[i].text == "..." {
				parameter.variadic = true
			}
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
	if signature, ok := parseGoFunctionSignature(source); ok {
		return signature.name, true
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
		if arg[0] >= arg[1] {
			continue
		}
		first := arg[0]
		if first < arg[1] && tokens[first].text == "async" {
			first++
		}
		if first >= arg[1] || tokens[first].kind != identifierToken {
			continue
		}
		name := tokens[first].text
		if first+1 < arg[1] && tokens[first].text == "async" && tokens[first+1].text == "(" {
			continue
		}
		if first+1 < arg[1] && tokens[first+1].text == "(" {
			if !seen[name] {
				names = append(names, name)
				seen[name] = true
			}
			continue
		}
		simpleReference := true
		for i := first + 1; i < arg[1]; i += 2 {
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
