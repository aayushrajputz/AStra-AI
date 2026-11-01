package analyzer

import (
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	gotoken "go/token"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type goSourceFile struct {
	file            *ast.File
	fileSet         *gotoken.FileSet
	imports         map[string]string
	explicitImports map[string]bool
	structs         map[string]map[string]string
}

type goRouter struct {
	framework string
	prefix    string
}

func parseGoSource(filename string, source []byte) (*goSourceFile, error) {
	fileSet := gotoken.NewFileSet()
	file, err := parser.ParseFile(fileSet, filename, source, parser.AllErrors)
	if err != nil {
		return nil, err
	}
	result := &goSourceFile{
		file: file, fileSet: fileSet, imports: make(map[string]string),
		explicitImports: make(map[string]bool),
		structs:         make(map[string]map[string]string),
	}
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return nil, fmt.Errorf("decode import path: %w", err)
		}
		alias := goImportName(importPath)
		if spec.Name != nil {
			alias = spec.Name.Name
			result.explicitImports[alias] = true
		}
		if alias != "_" && alias != "." {
			result.imports[alias] = importPath
		}
	}
	for _, declaration := range file.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != gotoken.TYPE {
			continue
		}
		for _, spec := range general.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				continue
			}
			fields := make(map[string]string)
			for _, field := range structType.Fields.List {
				fieldType := goTypeName(field.Type)
				if fieldType == "" {
					continue
				}
				for _, name := range field.Names {
					fields[name.Name] = fieldType
				}
			}
			result.structs[typeSpec.Name.Name] = fields
		}
	}
	return result, nil
}

func goImportName(importPath string) string {
	switch {
	case strings.Contains(importPath, "gin-gonic/gin"):
		return "gin"
	case strings.Contains(importPath, "go-chi/chi"):
		return "chi"
	case strings.Contains(importPath, "labstack/echo"):
		return "echo"
	default:
		return path.Base(importPath)
	}
}

func goTypeName(expression ast.Expr) string {
	var formatted strings.Builder
	if err := format.Node(&formatted, gotoken.NewFileSet(), expression); err != nil {
		return ""
	}
	return formatted.String()
}

func linkGoImports(root string, files []sourceFile) {
	modulePath := goModulePath(root)
	packages := make(map[string][]sourceFile)
	for _, file := range files {
		if file.goFile == nil {
			continue
		}
		directory := filepath.ToSlash(filepath.Dir(file.path))
		if directory == "." {
			directory = ""
		}
		packagePath := modulePath
		if directory != "" && modulePath != "" {
			packagePath += "/" + directory
		}
		packages[packagePath] = append(packages[packagePath], file)
	}
	for fileIndex := range files {
		file := &files[fileIndex]
		if file.goFile == nil {
			continue
		}
		for alias, importPath := range file.goFile.imports {
			importedFiles := packages[importPath]
			resolvedAlias := alias
			if !file.goFile.explicitImports[alias] && len(importedFiles) > 0 {
				resolvedAlias = importedFiles[0].goFile.file.Name.Name
				delete(file.goFile.imports, alias)
				file.goFile.imports[resolvedAlias] = importPath
			}
			for _, importedFile := range importedFiles {
				for _, declaration := range importedFile.goFile.file.Decls {
					function, ok := declaration.(*ast.FuncDecl)
					if !ok || !ast.IsExported(function.Name.Name) {
						continue
					}
					symbol := function.Name.Name
					if _, receiverType := goReceiver(function.Recv); receiverType != "" {
						symbol = receiverType + "." + symbol
					}
					key := resolvedAlias + "." + symbol
					file.imports[key] = importedSymbol{
						file: importedFile.path, symbol: symbol,
					}
				}
			}
		}
	}
}

func goModulePath(root string) string {
	contents, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(contents), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "module" {
			return fields[1]
		}
	}
	return ""
}

func parseGoFunctionSignature(source string) (functionSignature, bool) {
	if !strings.HasPrefix(strings.TrimSpace(source), "func ") &&
		!strings.HasPrefix(strings.TrimSpace(source), "func\t") {
		return functionSignature{}, false
	}
	fileSet := gotoken.NewFileSet()
	file, err := parser.ParseFile(fileSet, "signature.go", "package signature\n"+source, parser.AllErrors)
	if err != nil {
		return functionSignature{}, false
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		name := function.Name.Name
		if _, receiverType := goReceiver(function.Recv); receiverType != "" {
			name = receiverType + "." + name
		}
		parameters := make([]functionParameter, 0)
		if function.Type.Params != nil {
			for _, field := range function.Type.Params.List {
				typeName := goTypeName(field.Type)
				for _, parameterName := range field.Names {
					parameters = append(parameters, functionParameter{
						name: parameterName.Name, typeName: typeName,
						variadic: isGoVariadic(field.Type),
					})
				}
			}
		}
		return functionSignature{name: name, parameters: parameters}, true
	}
	return functionSignature{}, false
}

func isGoVariadic(expression ast.Expr) bool {
	_, ok := expression.(*ast.Ellipsis)
	return ok
}

func analyzeGoFiles(files []sourceFile) ([]Route, map[string][]functionInfo) {
	routes := make([]Route, 0)
	functions := make(map[string][]functionInfo)
	for _, file := range files {
		if file.goFile == nil {
			continue
		}
		routes = append(routes, goRoutesInFile(file)...)
		for _, declaration := range file.goFile.file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			name := function.Name.Name
			receiverName, receiverType := goReceiver(function.Recv)
			if receiverType != "" {
				name = receiverType + "." + name
			}
			definition := functionInfo{
				name: name, file: file.path,
				startLine: file.goFile.fileSet.Position(function.Pos()).Line,
				endLine:   file.goFile.fileSet.Position(function.End()).Line,
				imports:   file.imports,
			}
			calls := make(map[string]bool)
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch callable := call.Fun.(type) {
				case *ast.Ident:
					if callable.Name != "" && !isControlWord(callable.Name) {
						calls[callable.Name] = true
						definition.callSites = append(definition.callSites, goCallSite(definition.name,
							callable.Name, file, call))
					}
				case *ast.SelectorExpr:
					called := goCallName(callable, file, receiverName, receiverType)
					if called != "" {
						calls[called] = true
						definition.callSites = append(definition.callSites, goCallSite(definition.name,
							called, file, call))
					}
				}
				return true
			})
			for called := range calls {
				definition.calls = append(definition.calls, called)
			}
			sort.Strings(definition.calls)
			functions[name] = append(functions[name], definition)
		}
	}
	return routes, functions
}

func goCallSite(caller, callee string, file sourceFile, call *ast.CallExpr) CallSite {
	site := CallSite{
		Caller: caller, Callee: callee, File: file.path,
		Line:          file.goFile.fileSet.Position(call.Pos()).Line,
		ArgumentCount: len(call.Args),
		HasSpread:     call.Ellipsis.IsValid(),
	}
	for _, argument := range call.Args {
		if _, ok := argument.(*ast.KeyValueExpr); ok {
			site.HasNamedArgs = true
		}
	}
	return site
}

func goReceiver(fields *ast.FieldList) (string, string) {
	if fields == nil || len(fields.List) == 0 || len(fields.List[0].Names) == 0 {
		return "", ""
	}
	name := fields.List[0].Names[0].Name
	typeName := goTypeName(fields.List[0].Type)
	typeName = strings.TrimPrefix(typeName, "*")
	return name, typeName
}

func goCallName(call *ast.SelectorExpr, file sourceFile, receiverName, receiverType string) string {
	if identifier, ok := call.X.(*ast.Ident); ok {
		if _, imported := file.goFile.imports[identifier.Name]; imported {
			return identifier.Name + "." + call.Sel.Name
		}
		if identifier.Name == receiverName && receiverType != "" {
			return receiverType + "." + call.Sel.Name
		}
		if fields := file.goFile.structs[receiverType]; fields != nil {
			if fieldType := strings.TrimPrefix(fields[identifier.Name], "*"); fieldType != "" {
				return fieldType + "." + call.Sel.Name
			}
		}
		return call.Sel.Name
	}
	if nested, ok := call.X.(*ast.SelectorExpr); ok {
		if receiver, ok := nested.X.(*ast.Ident); ok && receiver.Name == receiverName {
			if fields := file.goFile.structs[receiverType]; fields != nil {
				if fieldType := strings.TrimPrefix(fields[nested.Sel.Name], "*"); fieldType != "" {
					return fieldType + "." + call.Sel.Name
				}
			}
		}
	}
	return call.Sel.Name
}

func goRoutesInFile(file sourceFile) []Route {
	routes := make([]Route, 0)
	for _, declaration := range file.goFile.file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		routers := make(map[string]goRouter)
		walkGoRoutes(file, function.Body, routers, goVariableTypes(function), &routes)
	}
	return routes
}

func goVariableTypes(function *ast.FuncDecl) map[string]string {
	variables := make(map[string]string)
	ast.Inspect(function.Body, func(node ast.Node) bool {
		switch current := node.(type) {
		case *ast.DeclStmt:
			general, ok := current.Decl.(*ast.GenDecl)
			if !ok || general.Tok != gotoken.VAR {
				break
			}
			for _, spec := range general.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok || value.Type == nil {
					continue
				}
				for _, name := range value.Names {
					variables[name.Name] = goTypeName(value.Type)
				}
			}
		case *ast.AssignStmt:
			if current.Tok != gotoken.DEFINE && current.Tok != gotoken.ASSIGN {
				break
			}
			for index, value := range current.Rhs {
				if index >= len(current.Lhs) {
					continue
				}
				name, ok := current.Lhs[index].(*ast.Ident)
				if !ok {
					continue
				}
				if typeName := goValueType(value); typeName != "" {
					variables[name.Name] = typeName
				}
			}
		}
		return true
	})
	return variables
}

func goValueType(expression ast.Expr) string {
	switch current := expression.(type) {
	case *ast.CompositeLit:
		return goTypeName(current.Type)
	case *ast.UnaryExpr:
		if current.Op == gotoken.AND {
			return goValueType(current.X)
		}
	case *ast.CallExpr:
		if identifier, ok := current.Fun.(*ast.Ident); ok && identifier.Name == "new" &&
			len(current.Args) == 1 {
			return "*" + goTypeName(current.Args[0])
		}
	}
	return ""
}

func walkGoRoutes(file sourceFile, block *ast.BlockStmt, routers map[string]goRouter,
	variables map[string]string, routes *[]Route) {
	for _, statement := range block.List {
		switch current := statement.(type) {
		case *ast.AssignStmt:
			for index, right := range current.Rhs {
				call, ok := right.(*ast.CallExpr)
				if !ok || index >= len(current.Lhs) {
					continue
				}
				name, ok := current.Lhs[index].(*ast.Ident)
				if !ok {
					continue
				}
				if router, ok := goRouterFactory(file, call); ok {
					routers[name.Name] = router
				} else if router, ok := goRouterGroup(call, routers); ok {
					routers[name.Name] = router
				} else if typeName := goValueType(right); typeName != "" {
					variables[name.Name] = typeName
				}
			}
		case *ast.DeclStmt:
			general, ok := current.Decl.(*ast.GenDecl)
			if !ok || general.Tok != gotoken.VAR {
				continue
			}
			for _, spec := range general.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for index, expression := range value.Values {
					call, ok := expression.(*ast.CallExpr)
					if !ok || index >= len(value.Names) {
						continue
					}
					if router, ok := goRouterFactory(file, call); ok {
						routers[value.Names[index].Name] = router
					} else if router, ok := goRouterGroup(call, routers); ok {
						routers[value.Names[index].Name] = router
					} else if value.Type != nil {
						variables[value.Names[index].Name] = goTypeName(value.Type)
					} else if typeName := goValueType(expression); typeName != "" {
						variables[value.Names[index].Name] = typeName
					}
				}
			}
		case *ast.ExprStmt:
			call, ok := current.X.(*ast.CallExpr)
			if !ok {
				continue
			}
			if goChiRoute(file, call, routers, variables, routes) {
				continue
			}
			goRouteCall(file, call, routers, variables, routes)
		case *ast.IfStmt:
			walkGoRoutes(file, current.Body, cloneGoRouters(routers), cloneStringMap(variables), routes)
		case *ast.BlockStmt:
			walkGoRoutes(file, current, cloneGoRouters(routers), cloneStringMap(variables), routes)
		}
	}
}

func cloneStringMap(values map[string]string) map[string]string {
	clone := make(map[string]string, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}

func cloneGoRouters(routers map[string]goRouter) map[string]goRouter {
	clone := make(map[string]goRouter, len(routers))
	for name, router := range routers {
		clone[name] = router
	}
	return clone
}

func goRouterFactory(file sourceFile, call *ast.CallExpr) (goRouter, bool) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return goRouter{}, false
	}
	packageName, ok := selector.X.(*ast.Ident)
	if !ok {
		return goRouter{}, false
	}
	importPath := file.goFile.imports[packageName.Name]
	switch {
	case strings.Contains(importPath, "gin-gonic/gin") && (selector.Sel.Name == "New" || selector.Sel.Name == "Default"):
		return goRouter{framework: "gin"}, true
	case strings.Contains(importPath, "go-chi/chi") && selector.Sel.Name == "NewRouter":
		return goRouter{framework: "chi"}, true
	case strings.Contains(importPath, "labstack/echo") && selector.Sel.Name == "New":
		return goRouter{framework: "echo"}, true
	default:
		return goRouter{}, false
	}
}

func goRouterGroup(call *ast.CallExpr, routers map[string]goRouter) (goRouter, bool) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || len(call.Args) == 0 {
		return goRouter{}, false
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok {
		return goRouter{}, false
	}
	parent, ok := routers[receiver.Name]
	if !ok || (selector.Sel.Name != "Group" && selector.Sel.Name != "With") {
		return goRouter{}, false
	}
	prefix, ok := goLiteralPath(call.Args[0])
	if !ok {
		if selector.Sel.Name == "With" {
			return parent, true
		}
		return goRouter{}, false
	}
	parent.prefix = joinPath(parent.prefix, prefix)
	return parent, true
}

func goChiRoute(file sourceFile, call *ast.CallExpr, routers map[string]goRouter,
	variables map[string]string, routes *[]Route) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Route" || len(call.Args) < 2 {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok {
		return false
	}
	parent, ok := routers[receiver.Name]
	if !ok || parent.framework != "chi" {
		return false
	}
	prefix, ok := goLiteralPath(call.Args[0])
	if !ok {
		return true
	}
	callback, ok := call.Args[1].(*ast.FuncLit)
	if !ok || callback.Body == nil || callback.Type.Params == nil ||
		len(callback.Type.Params.List) == 0 || len(callback.Type.Params.List[0].Names) == 0 {
		return true
	}
	child := cloneGoRouters(routers)
	name := callback.Type.Params.List[0].Names[0].Name
	child[name] = goRouter{framework: "chi", prefix: joinPath(parent.prefix, prefix)}
	childVariables := cloneStringMap(variables)
	childVariables[name] = "chi.Router"
	walkGoRoutes(file, callback.Body, child, childVariables, routes)
	return true
}

func goRouteCall(file sourceFile, call *ast.CallExpr, routers map[string]goRouter,
	variables map[string]string, routes *[]Route) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok {
		return
	}
	router, ok := routers[receiver.Name]
	if !ok || !goHTTPMethod(router.framework, selector.Sel.Name) || len(call.Args) < 2 {
		return
	}
	path, ok := goLiteralPath(call.Args[0])
	if !ok {
		return
	}
	handlers := make([]string, 0)
	for _, argument := range call.Args[1:] {
		handlers = append(handlers, goHandlerNames(argument, variables, file.goFile.imports)...)
	}
	*routes = append(*routes, Route{
		Method: goHTTPMethodName(selector.Sel.Name), Path: joinPath(router.prefix, path),
		File: file.path, Line: file.goFile.fileSet.Position(call.Pos()).Line,
		Handlers: handlers, Confidence: "heuristic",
	})
}

func goHTTPMethod(framework, method string) bool {
	switch {
	case framework == "chi":
		switch method {
		case "Connect", "Delete", "Get", "Head", "Options", "Patch", "Post", "Put", "Trace":
			return true
		}
	case framework == "gin" || framework == "echo":
		switch strings.ToUpper(method) {
		case "CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE":
			return true
		}
	}
	return false
}

func goHTTPMethodName(method string) string {
	return strings.ToUpper(method)
}

func goLiteralPath(expression ast.Expr) (string, bool) {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != gotoken.STRING {
		return "", false
	}
	value, err := strconv.Unquote(literal.Value)
	return value, err == nil
}

func goHandlerNames(expression ast.Expr, variables, imports map[string]string) []string {
	switch handler := expression.(type) {
	case *ast.Ident:
		return []string{handler.Name}
	case *ast.SelectorExpr:
		if prefix, ok := goSelectorPath(handler.X); ok {
			if _, imported := imports[prefix]; imported {
				return []string{prefix + "." + handler.Sel.Name}
			}
			if typeName := variables[prefix]; typeName != "" {
				return []string{strings.TrimPrefix(typeName, "*") + "." + handler.Sel.Name}
			}
			return []string{prefix + "." + handler.Sel.Name}
		}
	case *ast.CallExpr:
		if len(handler.Args) > 0 {
			return goHandlerNames(handler.Args[0], variables, imports)
		}
	}
	return nil
}

func goSelectorPath(expression ast.Expr) (string, bool) {
	switch current := expression.(type) {
	case *ast.Ident:
		return current.Name, true
	case *ast.SelectorExpr:
		prefix, ok := goSelectorPath(current.X)
		if !ok {
			return "", false
		}
		return prefix + "." + current.Sel.Name, true
	}
	return "", false
}
