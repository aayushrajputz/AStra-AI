package analyzer

import (
	"fmt"
	"go/ast"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/astra-ai/astra/internal/diff"
)

type contractField struct {
	name     string
	typeName string
	optional bool
	column   int
	line        int
	constraints string
	enumValues  string
}

type contractSchema struct {
	name      string
	file      string
	startLine int
	endLine   int
	fields    map[string]contractField
	review    bool
}

type contractReference struct {
	name string
	file string
}

type routeContract struct {
	request  []contractReference
	response []contractReference
}

type contractFinding struct {
	route    Route
	reason   string
	severity string
}

type contractDiffResult struct {
	findings       []contractFinding
	handledChanges map[int]bool
}

func indexContractSchemas(files []sourceFile) map[string]contractSchema {
	schemas := make(map[string]contractSchema)
	aliases := make(map[string]string)
	for _, file := range files {
		tokens := file.tokens
		for i := 0; i+1 < len(tokens); i++ {
			switch tokens[i].text {
			case "interface":
				if tokens[i+1].kind != identifierToken {
					continue
				}
				open := i + 2
				for open < len(tokens) && tokens[open].text != "{" && tokens[open].text != ";" {
					open++
				}
				if open < len(tokens) && tokens[open].text == "{" {
					close := matchingToken(tokens, open, "{", "}")
					if close > open {
						schemas[file.path+"\x00"+tokens[i+1].text] = contractSchema{
							name: tokens[i+1].text, file: file.path,
							startLine: tokens[open].line, endLine: tokens[close].line,
							fields: parseContractFields(tokens, open+1, close, false),
						}
					}
				}
			case "type":
				if tokens[i+1].kind != identifierToken {
					continue
				}
				equal := i + 2
				for equal < len(tokens) && tokens[equal].text != "=" && tokens[equal].text != ";" {
					equal++
				}
				if equal+1 < len(tokens) && tokens[equal].text == "=" && tokens[equal+1].text == "{" {
					close := matchingToken(tokens, equal+1, "{", "}")
					if close > equal+1 {
						schemas[file.path+"\x00"+tokens[i+1].text] = contractSchema{
							name: tokens[i+1].text, file: file.path,
							startLine: tokens[equal+1].line, endLine: tokens[close].line,
							fields: parseContractFields(tokens, equal+2, close, false),
						}
					}
				} else if equal+1 < len(tokens) && tokens[equal].text == "=" {
					if target := inferredSchemaName(tokens, equal+1); target != "" {
						aliases[file.path+"\x00"+tokens[i+1].text] = target
					}
				}
			case "class":
				if tokens[i+1].kind != identifierToken {
					continue
				}
				open := i + 2
				for open < len(tokens) && tokens[open].text != "{" && tokens[open].text != ";" {
					open++
				}
				if open < len(tokens) && tokens[open].text == "{" {
					close := matchingToken(tokens, open, "{", "}")
					if close > open {
						fields := parseClassContractFields(tokens, open+1, close)
						if len(fields) > 0 {
							schemas[file.path+"\x00"+tokens[i+1].text] = contractSchema{
								name: tokens[i+1].text, file: file.path,
								startLine: tokens[open].line, endLine: tokens[close].line, fields: fields,
							}
						}
					}
				}
			}
		}

		for i := 1; i+3 < len(tokens); i++ {
			if tokens[i].text != "object" || tokens[i-1].text != "." ||
				tokens[i+1].text != "(" || tokens[i+2].text != "{" {
				continue
			}
			closeArgs := matchingToken(tokens, i+1, "(", ")")
			closeObject := matchingToken(tokens, i+2, "{", "}")
			if closeArgs < 0 || closeObject < 0 || closeObject >= closeArgs {
				continue
			}
			name := assignedName(tokens, i)
			if name == "" {
				continue
			}
			expressionEnd := declarationEnd(tokens, i)
			schemas[file.path+"\x00"+name] = contractSchema{
				name: name, file: file.path,
				startLine: tokens[i+2].line, endLine: tokens[expressionEnd].line,
				fields: parseContractFields(tokens, i+3, closeObject, true),
				review: zodSchemaNeedsReview(tokens, i, expressionEnd),
			}
		}
		for _, declaration := range file.goFileDeclarations() {
			general, ok := declaration.(*ast.GenDecl)
			if !ok || general.Tok.String() != "type" {
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
				fields := make(map[string]contractField)
				for _, field := range structType.Fields.List {
					if field.Tag == nil {
						continue
					}
					tagValue, err := strconv.Unquote(field.Tag.Value)
					if err != nil {
						continue
					}
					tag := reflect.StructTag(tagValue)
					jsonName := strings.Split(tag.Get("json"), ",")[0]
					if jsonName == "-" {
						continue
					}
					for _, fieldName := range field.Names {
						if jsonName == "" {
							jsonName = fieldName.Name
						}
						optional := !containsTagValue(tag.Get("binding"), "required") &&
							!containsTagValue(tag.Get("validate"), "required")
						if containsTagValue(tag.Get("json"), "omitempty") ||
							containsTagValue(tag.Get("json"), "omitzero") {
							optional = true
						}
						fields[jsonName] = contractField{
							name: jsonName, typeName: goTypeName(field.Type), optional: optional,
							column: 0,
						}
					}
				}
				if len(fields) == 0 {
					continue
				}
				schemas[file.path+"\x00"+typeSpec.Name.Name] = contractSchema{
					name: typeSpec.Name.Name, file: file.path,
					startLine: file.goFile.fileSet.Position(typeSpec.Pos()).Line,
					endLine:   file.goFile.fileSet.Position(typeSpec.End()).Line,
					fields:    fields,
				}
			}
		}
	}
	for range len(aliases) {
		changed := false
		for aliasKey, target := range aliases {
			if _, exists := schemas[aliasKey]; exists {
				continue
			}
			file, name, ok := splitSchemaKey(aliasKey)
			if !ok {
				continue
			}
			targetSchema, exists := schemas[file+"\x00"+target]
			if !exists {
				continue
			}
			targetSchema.name = name
			schemas[aliasKey] = targetSchema
			changed = true
		}
		if !changed {
			break
		}
	}
	return schemas
}

func zodSchemaNeedsReview(tokens []token, start, end int) bool {
	for i := start; i < end; i++ {
		if tokens[i].text == "..." {
			return true
		}
		if tokens[i].text == "." && i+1 < end {
			switch tokens[i+1].text {
			case "refine", "transform", "superRefine", "pick", "omit", "extend", "merge":
				return true
			}
		}
	}
	return false
}

func (file sourceFile) goFileDeclarations() []ast.Decl {
	if file.goFile == nil {
		return nil
	}
	return file.goFile.file.Decls
}

func containsTagValue(value, expected string) bool {
	for _, part := range strings.Split(value, ",") {
		if part == expected {
			return true
		}
	}
	return false
}

func inferredSchemaName(tokens []token, start int) string {
	for i := start; i+1 < len(tokens); i++ {
		if tokens[i].text == "typeof" && tokens[i+1].kind == identifierToken {
			return tokens[i+1].text
		}
		if tokens[i].text == ";" || tokens[i].text == "}" {
			break
		}
	}
	return ""
}

func splitSchemaKey(key string) (string, string, bool) {
	separator := strings.IndexByte(key, '\x00')
	if separator < 0 {
		return "", "", false
	}
	return key[:separator], key[separator+1:], true
}

func assignedName(tokens []token, index int) string {
	for i := index - 1; i >= 1 && index-i <= 12; i-- {
		if tokens[i].text == "=" && tokens[i-1].kind == identifierToken {
			return tokens[i-1].text
		}
		if tokens[i].text == ";" || tokens[i].text == "{" || tokens[i].text == "}" {
			break
		}
	}
	return ""
}

func parseContractFields(tokens []token, start, end int, zod bool) map[string]contractField {
	return parseContractFieldsWithPrefix(tokens, start, end, zod, "")
}

func parseContractFieldsWithPrefix(tokens []token, start, end int, zod bool, prefix string) map[string]contractField {
	fields := make(map[string]contractField)
	for _, member := range splitContractMembers(tokens, start, end) {
		colon := -1
		field := contractField{line: tokens[member[0]].line}
		for i := member[0]; i < member[1]; i++ {
			if tokens[i].text == ":" {
				colon = i
				break
			}
			if tokens[i].kind == identifierToken || tokens[i].kind == stringToken {
				field.name = strings.Trim(tokens[i].text, `"'`)
				field.column = tokens[i].column
			}
			if tokens[i].text == "?" {
				field.optional = true
			}
		}
		if colon < 0 || field.name == "" {
			continue
		}
		field.name = prefix + field.name
		for i := colon + 1; i < member[1]; i++ {
			field.typeName += tokens[i].text
			if tokens[i].text == "?" && i+1 < member[1] && tokens[i+1].text == "." &&
				i+2 < member[1] && tokens[i+2].text == "optional" {
				field.optional = true
			}
		}
		if zod {
			field.typeName = zodFieldType(tokens, colon+1, member[1])
			field.optional = field.optional || zodOptional(tokens, colon+1, member[1])
			field.constraints = zodConstraintSignature(tokens, colon+1, member[1])
			field.enumValues = zodEnumValues(tokens, colon+1, member[1])
			for i := colon + 1; i+2 < member[1]; i++ {
				if tokens[i].text != "z" || tokens[i+1].text != "." ||
					tokens[i+2].text != "object" {
					continue
		}
				open := i + 3
				for open < member[1] && tokens[open].text != "{" {
					open++
				}
				if open >= member[1] {
					continue
				}
				close := matchingToken(tokens, open, "{", "}")
				if close < 0 || close > member[1] {
					continue
				}
				nested := parseContractFieldsWithPrefix(tokens, open+1, close, true, field.name+".")
				for name, child := range nested {
					fields[name] = child
				}
				break
			}
		}
		if field.name != "" && field.typeName != "" {
			fields[field.name] = field
		}
	}
	return fields
}

func zodOptional(tokens []token, start, end int) bool {
	for i := start; i+1 < end; i++ {
		if tokens[i].text == "." && (tokens[i+1].text == "optional" ||
			tokens[i+1].text == "nullish" || tokens[i+1].text == "default") {
			return true
		}
	}
	return false
}

func zodConstraintSignature(tokens []token, start, end int) string {
	var constraints []string
	for i := start; i+1 < end; i++ {
		if tokens[i].text == "." && (tokens[i+1].text == "min" || tokens[i+1].text == "max" ||
			tokens[i+1].text == "email" || tokens[i+1].text == "regex" || tokens[i+1].text == "length") {
			constraints = append(constraints, tokens[i+1].text)
		}
	}
	sort.Strings(constraints)
	return strings.Join(constraints, ",")
}

func zodEnumValues(tokens []token, start, end int) string {
	for i := start; i+3 < end; i++ {
		if tokens[i].text != "z" || tokens[i+1].text != "." ||
			tokens[i+2].text != "enum" || tokens[i+3].text != "(" {
			continue
		}
		open := i + 4
		for open < end && tokens[open].text != "[" {
			open++
		}
		if open >= end {
			return ""
		}
		close := matchingToken(tokens, open, "[", "]")
		if close < 0 || close > end {
			return ""
		}
		var values []string
		for index := open + 1; index < close; index++ {
			if tokens[index].kind == stringToken {
				values = append(values, strings.Trim(tokens[index].text, `"'`))
			}
		}
		sort.Strings(values)
		return strings.Join(values, ",")
	}
	return ""
}

func splitContractMembers(tokens []token, start, end int) [][2]int {
	members := make([][2]int, 0)
	begin, depth := start, 0
	for i := start; i < end; i++ {
		switch tokens[i].text {
		case "(", "[", "{", "<":
			depth++
		case ")", "]", "}", ">":
			depth--
		case ";", ",":
			if depth == 0 {
				if begin < i {
					members = append(members, [2]int{begin, i})
				}
				begin = i + 1
			}
		}
	}
	if begin < end {
		members = append(members, [2]int{begin, end})
	}
	return members
}

func zodFieldType(tokens []token, start, end int) string {
	for i := start; i+2 < end; i++ {
		if tokens[i].text != "z" || tokens[i+1].text != "." {
			continue
		}
		base := ""
		switch tokens[i+2].text {
		case "string":
			base = "string"
		case "number":
			base = "number"
		case "boolean":
			base = "boolean"
		case "date":
			base = "Date"
		case "array":
			for j := i + 3; j+2 < end; j++ {
				if tokens[j].text != "z" || tokens[j+1].text != "." {
					continue
				}
				switch tokens[j+2].text {
				case "string", "number", "boolean", "date":
					elementType := zodPrimitiveType(tokens[j+2].text)
					base = "array<" + elementType + ">"
				}
				if base != "" {
					break
				}
			}
		case "object":
			base = "object"
		case "enum":
			return "enum"
		case "literal":
			return "literal"
		case "union":
			return "union"
		case "record":
			return "record"
		case "tuple":
			return "tuple"
		}
		if base != "" {
				return base
			}
		}
	return "zod:" + normalizedZodExpression(tokens, start, end)
}

func normalizedZodExpression(tokens []token, start, end int) string {
	normalized := make([]token, 0, end-start)
	for i := start; i < end; i++ {
		if tokens[i].text == "." && i+1 < end && tokens[i+1].text == "optional" {
			i++
			if i+1 < end && tokens[i+1].text == "(" {
				i++
				if i+1 < end && tokens[i+1].text == ")" {
					i++
				}
			}
			continue
		}
		normalized = append(normalized, tokens[i])
	}
	return tokenText(normalized, 0, len(normalized))
}

func zodPrimitiveType(name string) string {
	if name == "date" {
		return "Date"
	}
	return name
}

func parseClassContractFields(tokens []token, start, end int) map[string]contractField {
	fields := make(map[string]contractField)
	for i := start; i+1 < end; {
		if tokens[i].text == "@" && i+2 < end {
			if tokens[i+2].text == "(" {
				if close := matchingToken(tokens, i+2, "(", ")"); close > i {
					i = close + 1
					continue
				}
			}
			i += 2
			continue
		}
		if tokens[i].kind != identifierToken {
			i++
			continue
		}
		if tokens[i+1].text == "(" {
			close := matchingToken(tokens, i+1, "(", ")")
			if close > i {
				body := close + 1
				for body < end && tokens[body].text != "{" && tokens[body].text != ";" {
					body++
				}
				if body < end && tokens[body].text == "{" {
					if bodyClose := matchingToken(tokens, body, "{", "}"); bodyClose > body && bodyClose < end {
						i = bodyClose + 1
						continue
					}
				}
				i = close + 1
				continue
			}
		}
		if tokens[i+1].text != ":" && tokens[i+1].text != "?" &&
			!(i+2 < end && tokens[i+1].text == "!" && tokens[i+2].text == ":") {
			i++
			continue
		}
		field := contractField{name: tokens[i].text, column: tokens[i].column}
		typeStart := i + 1
		if tokens[typeStart].text == "?" {
			field.optional = true
			typeStart++
		} else if tokens[typeStart].text == "!" {
			typeStart++
		}
		if typeStart >= end || tokens[typeStart].text != ":" {
			i++
			continue
		}
		typeStart++
		typeEnd := typeStart
		for typeEnd < end && tokens[typeEnd].text != ";" && tokens[typeEnd].text != "=" &&
			tokens[typeEnd].line == tokens[typeStart].line {
			field.typeName += tokens[typeEnd].text
			typeEnd++
		}
		if field.typeName == "" {
			i++
			continue
		}
		lineStart := i - 1
		for lineStart >= start && tokens[lineStart].text != ";" && tokens[lineStart].text != "}" {
			if tokens[lineStart].text == ":" && tokens[lineStart].line < tokens[i].line {
				break
			}
			if tokens[lineStart].text == "IsOptional" {
				field.optional = true
			}
			lineStart--
		}
		fields[field.name] = field
		i = typeEnd
	}
	return fields
}

func indexRouteContracts(routes []Route, files []sourceFile, schemas map[string]contractSchema) map[string]routeContract {
	fileByPath := make(map[string]sourceFile, len(files))
	symbols := indexTopLevelSymbols(files)
	byName := make(map[string]map[string]bool)
	for _, file := range files {
		fileByPath[file.path] = file
		for _, symbol := range symbols {
			if symbol.file == file.path {
				if byName[file.path] == nil {
					byName[file.path] = make(map[string]bool)
	}
				byName[file.path][symbol.name] = true
			}
		}
	}
	functions := indexFunctions(files)
	bindings := make(map[string]routeContract)
	for _, route := range routes {
		file, ok := fileByPath[route.File]
		if !ok {
			continue
		}
		binding := routeContract{}
		for _, handler := range route.Handlers {
			if file.goFile != nil {
				binding.request = append(binding.request, goHandlerRequestSchemas(
					handler, file, fileByPath, schemas)...)
				continue
			}
			requestType, responseType := handlerContractTypes(file, handler)
			if name := findSchemaReference(requestType, file, schemas); name != "" {
				binding.request = appendUniqueContractRef(binding.request, resolveSchemaReference(name, file, schemas))
			}
			if name := findSchemaReference(responseType, file, schemas); name != "" {
				binding.response = appendUniqueContractRef(binding.response, resolveSchemaReference(name, file, schemas))
			}
			targetName, targetFile := handler, file
			if imported, exists := file.imports[handler]; exists {
				targetName = imported.symbol
				targetFile = fileByPath[imported.file]
		}
			for _, definition := range functions[targetName] {
				if definition.file != targetFile.path || !functionUsesRequestParser(definition, fileByPath, byName, symbols, schemas) {
					continue
				}
				targetSource := fileByPath[definition.file]
				for index := definition.bodyStart; index < definition.bodyEnd; index++ {
					if targetSource.tokens[index].kind != identifierToken {
						continue
					}
					schemaID, ok := resolveSymbolID(definition.file, targetSource.tokens[index].text,
						byName, definition.imports, symbols)
					if !ok {
						continue
					}
					if _, exists := schemas[schemaID]; exists {
						schemaFile, schemaName, _ := splitSchemaKey(schemaID)
						binding.request = appendUniqueContractRef(binding.request, contractReference{
							name: schemaName, file: schemaFile,
						})
					}
				}
			}
		}
		for _, dependency := range route.DepSymbols {
			file, name, ok := splitSchemaKey(dependency)
			if !ok {
				continue
			}
			if _, exists := schemas[dependency]; exists && routeUsesValidationMiddleware(route) {
				binding.request = appendUniqueContractRef(binding.request, contractReference{
					name: name, file: file,
				})
			}
		}
		bindings[routeKey(route)] = binding
	}
	return bindings
}

func functionUsesRequestParser(definition functionInfo, files map[string]sourceFile,
	byName map[string]map[string]bool, symbols map[string]topLevelSymbol,
	schemas map[string]contractSchema) bool {
	file, exists := files[definition.file]
	if !exists {
		return false
	}
	hasParser, hasRequest := false, false
	for index := definition.bodyStart; index < definition.bodyEnd; index++ {
		switch file.tokens[index].text {
		case "parse", "safeParse":
			hasParser = true
		case "req", "request":
			hasRequest = true
		}
	}
	if !hasParser || !hasRequest {
		return false
	}
	for index := definition.bodyStart; index < definition.bodyEnd; index++ {
		if file.tokens[index].kind != identifierToken {
			continue
		}
		if symbolID, ok := resolveSymbolID(definition.file, file.tokens[index].text,
			byName, definition.imports, symbols); ok {
			if _, isSchema := schemas[symbolID]; isSchema {
				return true
			}
		}
	}
	return false
}

func routeUsesValidationMiddleware(route Route) bool {
	for _, middleware := range route.Middlewares {
		if strings.Contains(strings.ToLower(middleware), "validat") {
			return true
		}
	}
	return false
}

func goHandlerRequestSchemas(handler string, routeFile sourceFile, files map[string]sourceFile,
	schemas map[string]contractSchema) []contractReference {
	targetFile := routeFile
	targetName := handler
	if imported, ok := routeFile.imports[handler]; ok {
		targetFile = files[imported.file]
		targetName = imported.symbol
	}
	if targetFile.goFile == nil {
		return nil
	}
	var result []contractReference
	for _, declaration := range targetFile.goFile.file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != targetName || function.Body == nil {
			continue
		}
		hasBinder := false
		types := make(map[string]bool)
		ast.Inspect(function.Body, func(node ast.Node) bool {
			switch current := node.(type) {
			case *ast.CallExpr:
				if selector, ok := current.Fun.(*ast.SelectorExpr); ok &&
					(strings.Contains(selector.Sel.Name, "Bind") || strings.Contains(selector.Sel.Name, "Decode")) {
					hasBinder = true
				}
			case *ast.ValueSpec:
				if current.Type != nil {
					if name := goSchemaTypeName(current.Type); name != "" {
						types[name] = true
					}
				}
			case *ast.CompositeLit:
				if name := goSchemaTypeName(current.Type); name != "" {
					types[name] = true
				}
			}
			return true
		})
		if !hasBinder {
			continue
		}
		for name := range types {
			if _, exists := schemas[targetFile.path+"\x00"+name]; exists {
				result = appendUniqueContractRef(result, contractReference{
					name: name, file: targetFile.path,
				})
			}
		}
	}
	return result
}

func goSchemaTypeName(expression ast.Expr) string {
	switch current := expression.(type) {
	case *ast.Ident:
		return current.Name
	case *ast.StarExpr:
		return goSchemaTypeName(current.X)
	case *ast.SelectorExpr:
		return current.Sel.Name
	}
	return ""
}

func appendUniqueContractRef(references []contractReference, reference contractReference) []contractReference {
	for _, existing := range references {
		if existing == reference {
			return references
		}
	}
	return append(references, reference)
}

func resolveSchemaReference(name string, file sourceFile, schemas map[string]contractSchema) contractReference {
	if _, ok := schemas[file.path+"\x00"+name]; ok {
		return contractReference{name: name, file: file.path}
	}
	if imported, ok := file.imports[name]; ok {
		if _, exists := schemas[imported.file+"\x00"+imported.symbol]; exists {
			return contractReference{name: imported.symbol, file: imported.file}
		}
	}
	return contractReference{}
}

func findSchemaReference(typeName string, file sourceFile, schemas map[string]contractSchema) string {
	if typeName == "" {
		return ""
	}
	tokens, err := lex(typeName)
	if err != nil {
		return ""
	}
	for _, token := range tokens {
		if token.kind != identifierToken {
			continue
		}
		if _, ok := schemas[file.path+"\x00"+token.text]; ok {
			return token.text
		}
		if imported, ok := file.imports[token.text]; ok {
			if _, exists := schemas[imported.file+"\x00"+imported.symbol]; exists {
				return token.text
			}
		}
	}
	return ""
}

func handlerContractTypes(file sourceFile, handler string) (string, string) {
	name := handler
	if dot := strings.LastIndexByte(name, '.'); dot >= 0 {
		name = name[dot+1:]
	}
	tokens := file.tokens
	for i := 0; i+1 < len(tokens); i++ {
		if tokens[i].text == "function" && tokens[i+1].text == name {
			if i+2 < len(tokens) && tokens[i+2].text == "(" {
				return parameterAndReturnTypes(tokens, i+2)
			}
		}
		if tokens[i].text == name && tokens[i+1].text == "(" &&
			isLikelyFunctionDeclaration(tokens, i) {
			return parameterAndReturnTypes(tokens, i+1)
		}
		if tokens[i].text == name && tokens[i+1].text == "=" {
			open := i + 2
			for open < len(tokens) && tokens[open].text != "(" && tokens[open].text != "=>" &&
				tokens[open].text != ";" {
				open++
			}
			if open < len(tokens) && tokens[open].text == "(" {
				if close := matchingToken(tokens, open, "(", ")"); close > open {
					for next := close + 1; next < len(tokens) && tokens[next].text != ";" &&
						tokens[next].text != "{"; next++ {
						if tokens[next].text == "=>" {
							return parameterAndReturnTypes(tokens, open)
						}
					}
				}
			}
		}
	}
	return "", ""
}

func isLikelyFunctionDeclaration(tokens []token, nameIndex int) bool {
	if nameIndex+1 >= len(tokens) || tokens[nameIndex+1].text != "(" {
		return false
	}
	close := matchingToken(tokens, nameIndex+1, "(", ")")
	if close < 0 {
		return false
	}
	for i := close + 1; i < len(tokens) && i <= close+8; i++ {
		switch tokens[i].text {
		case "{", "=>":
			return true
		case ";", "=":
			return false
		}
	}
	return false
}

func parameterAndReturnTypes(tokens []token, open int) (string, string) {
	close := matchingToken(tokens, open, "(", ")")
	if close < 0 {
		return "", ""
	}
	var requestType, responseType string
	for parameterIndex, argument := range splitSignatureArguments(tokens, open+1, close) {
		colon := -1
		for i := argument[0]; i < argument[1]; i++ {
			if tokens[i].text == ":" {
				colon = i
				break
			}
		}
		if colon < 0 {
			continue
		}
		typeName := tokenText(tokens, colon+1, argument[1])
		if parameterIndex == 0 {
			requestType = requestBodyType(typeName)
		} else if responseType == "" {
			responseType = responseBodyType(typeName)
		}
	}
	returnType := ""
	for i := close + 1; i < len(tokens); i++ {
		if tokens[i].text == "{" || tokens[i].text == "=>" || tokens[i].text == ";" {
			break
		}
		if tokens[i].text == ":" {
			start := i + 1
			end := start
			for end < len(tokens) && tokens[end].text != "{" && tokens[end].text != "=>" &&
				tokens[end].text != ";" {
				end++
			}
			returnType = tokenText(tokens, start, end)
			break
		}
	}
	if returnType != "" {
		responseType = returnType
	}
	return requestType, responseType
}

func requestBodyType(typeName string) string {
	tokens, err := lex(typeName)
	if err != nil {
		return typeName
	}
	for i := 0; i+1 < len(tokens); i++ {
		if tokens[i].text == "Request" || tokens[i].text == "FastifyRequest" {
			if tokens[i+1].text == "<" {
				args := splitTypeArguments(tokens, i+2)
				if len(args) >= 3 {
					return tokenText(tokens, args[2][0], args[2][1])
				}
			}
		}
	}
	return typeName
}

func responseBodyType(typeName string) string {
	tokens, err := lex(typeName)
	if err != nil {
		return typeName
	}
	for i := 0; i+1 < len(tokens); i++ {
		if tokens[i].text == "Response" || tokens[i].text == "FastifyReply" {
			if tokens[i+1].text == "<" {
				args := splitTypeArguments(tokens, i+2)
				if len(args) > 0 {
					return tokenText(tokens, args[0][0], args[0][1])
				}
			}
		}
	}
	return typeName
}

func splitTypeArguments(tokens []token, start int) [][2]int {
	depth, begin := 0, start
	args := make([][2]int, 0)
	for i := start; i < len(tokens); i++ {
		switch tokens[i].text {
		case "<":
			depth++
		case ">":
			if depth == 0 {
				if begin < i {
					args = append(args, [2]int{begin, i})
				}
				return args
			}
			depth--
		case ",":
			if depth == 0 {
				args = append(args, [2]int{begin, i})
				begin = i + 1
			}
		}
	}
	return args
}

func splitSignatureArguments(tokens []token, start, end int) [][2]int {
	args := make([][2]int, 0)
	begin, depth := start, 0
	for i := start; i < end; i++ {
		switch tokens[i].text {
		case "(", "[", "{", "<":
			depth++
		case ")", "]", "}", ">":
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

func tokenText(tokens []token, start, end int) string {
	var text strings.Builder
	previousIdentifier := false
	for i := start; i < end && i < len(tokens); i++ {
		if previousIdentifier && tokens[i].kind == identifierToken {
			text.WriteByte(' ')
		}
		text.WriteString(tokens[i].text)
		previousIdentifier = tokens[i].kind == identifierToken
	}
	return text.String()
}

func changedContractField(source string) (contractField, bool) {
	tokens, err := lex(source)
	if err != nil {
		return contractField{}, false
	}
	if field, ok := changedGoContractField(tokens); ok {
		return field, true
	}
	for i := 0; i+1 < len(tokens); i++ {
		if tokens[i].kind != identifierToken {
			continue
		}
		colon := i + 1
		field := contractField{name: tokens[i].text, column: tokens[i].column}
		if tokens[colon].text == "?" {
			field.optional = true
			colon++
		}
		if colon >= len(tokens) || tokens[colon].text != ":" {
			continue
		}
		end, depth := colon+1, 0
		for end < len(tokens) {
			switch tokens[end].text {
			case "(", "[", "{":
				depth++
			case ")", "]", "}":
				depth--
			case ";", "=":
				if depth == 0 {
					goto expressionDone
				}
			case ",":
				if depth == 0 {
					goto expressionDone
				}
			}
			if tokens[end].text == "." && end+1 < len(tokens) && tokens[end+1].text == "optional" {
				field.optional = true
			}
			field.typeName += tokens[end].text
			end++
		}
	expressionDone:
		if field.typeName == "" {
			return contractField{}, false
		}
		if strings.Contains(field.typeName, "z.") {
			field.typeName = changedZodType(field.typeName)
			field.optional = field.optional || strings.Contains(source, ".optional")
			field.constraints = zodConstraintSignature(tokens, colon+1, end)
			field.enumValues = zodEnumValues(tokens, colon+1, end)
		}
		return field, true
	}
	return contractField{}, false
}

func changedGoContractField(tokens []token) (contractField, bool) {
	if len(tokens) < 2 || tokens[0].kind != identifierToken || tokens[1].kind != identifierToken {
		return contractField{}, false
	}
	field := contractField{
		name: tokens[0].text, typeName: tokens[1].text, column: tokens[0].column, optional: true,
	}
	if len(tokens) > 2 && tokens[2].kind == stringToken {
		tag := reflect.StructTag(tokens[2].text)
		jsonTag := strings.Split(tag.Get("json"), ",")
		if len(jsonTag) > 0 && jsonTag[0] != "" && jsonTag[0] != "-" {
			field.name = jsonTag[0]
		}
		field.optional = !containsTagValue(tag.Get("binding"), "required") &&
			!containsTagValue(tag.Get("validate"), "required")
	}
	return field, true
}

func changedZodType(typeName string) string {
	tokens, err := lex(typeName)
	if err != nil {
		return "zod:" + typeName
	}
	return zodFieldType(tokens, 0, len(tokens))
}

func contractChanges(changes []diff.Change) (map[int]contractField, map[int]contractField) {
	oldFields, newFields := make(map[int]contractField), make(map[int]contractField)
	for index, change := range changes {
		field, ok := changedContractField(change.Text)
		if !ok {
			continue
		}
		if change.Kind == diff.DeletedChange {
			oldFields[index] = field
		} else if change.Kind == diff.AddedChange {
			newFields[index] = field
		}
	}
	return oldFields, newFields
}

func classifyContractChanges(route Route, binding routeContract, schemas map[string]contractSchema,
	change diff.File) contractDiffResult {
	result := contractDiffResult{handledChanges: make(map[int]bool)}
	oldFields, newFields := contractChanges(change.Changes)
	type directionReference struct {
		label      string
		references []contractReference
	}
	directions := []directionReference{
		{label: "request", references: binding.request},
		{label: "response", references: binding.response},
	}
	for _, direction := range directions {
		for _, reference := range direction.references {
			if reference.file != change.Path {
				continue
			}
			schema, exists := schemas[reference.file+"\x00"+reference.name]
			if !exists || !schema.review {
				continue
			}
			for index, changed := range change.Changes {
				if result.handledChanges[index] || !schemaContainsChangeLine(schema, changed, changed.Kind == diff.AddedChange) {
					continue
				}
				result.findings = append(result.findings, contractFinding{
					route: route, severity: "body-changed",
					reason: "schema logic changed - review",
				})
				result.handledChanges[index] = true
			}
		}
	}
	for index, oldField := range oldFields {
		for newIndex, newField := range newFields {
			if oldField.name != newField.name {
				continue
			}
			for _, direction := range directions {
				for _, reference := range direction.references {
					if reference.file != change.Path {
						continue
					}
					schema, exists := schemas[reference.file+"\x00"+reference.name]
					if !exists {
						continue
					}
					if !schemaContainsChangeLine(schema, change.Changes[index], false) {
						continue
					}
					if !schemaContainsChangeLine(schema, change.Changes[newIndex], true) {
						continue
					}
					current, fieldExists := schemaFieldForChange(schema, newField, change.Changes[newIndex], true)
					if !fieldExists || current.name != schemaFieldNameForChange(schema, oldField, change.Changes[index], false) {
						continue
					}
					oldField.name = current.name
					newField.name = current.name
					severity, reason := classifyChangedContractField(direction.label, oldField, newField)
					if severity != "" {
						result.findings = append(result.findings, contractFinding{
							route: route, severity: severity, reason: reason,
						})
					}
					result.handledChanges[index] = true
					result.handledChanges[newIndex] = true
				}
			}
		}
	}
	for index, oldField := range oldFields {
		if result.handledChanges[index] {
			continue
		}
		for _, direction := range directions {
			for _, reference := range direction.references {
				if reference.file != change.Path {
					continue
				}
				schema, exists := schemas[reference.file+"\x00"+reference.name]
				if !exists {
					continue
				}
				if !schemaContainsChangeLine(schema, change.Changes[index], false) {
					continue
				}
				if _, exists := schemaFieldForChange(schema, oldField, change.Changes[index], false); exists {
					continue
				}
				matchesTopLevelColumn := len(schema.fields) == 0
				for _, field := range schema.fields {
					if field.column == oldField.column {
						matchesTopLevelColumn = true
						break
					}
				}
				if !matchesTopLevelColumn {
					continue
				}
				result.findings = append(result.findings, contractFinding{
					route: route, severity: "breaking",
					reason: fmt.Sprintf("%s field %q was removed", direction.label,
						nestedContractFieldName(schema, oldField, change.Changes[index])),
				})
				result.handledChanges[index] = true
			}
		}
	}
	for index, newField := range newFields {
		if result.handledChanges[index] {
			continue
		}
		for _, direction := range directions {
			for _, reference := range direction.references {
				if reference.file != change.Path {
					continue
				}
				schema, exists := schemas[reference.file+"\x00"+reference.name]
				if !exists {
					continue
				}
				if !schemaContainsChangeLine(schema, change.Changes[index], true) {
					continue
				}
				current, exists := schemaFieldForChange(schema, newField, change.Changes[index], true)
				if !exists || current.typeName != newField.typeName {
					continue
				}
				newField.name = current.name
				severity := "non-breaking"
				reason := fmt.Sprintf("%s field %q was added", direction.label, newField.name)
				if direction.label == "request" && !current.optional {
					severity = "breaking"
					reason = fmt.Sprintf("required request field %q was added", newField.name)
				} else if direction.label == "request" {
					reason = fmt.Sprintf("optional request field %q was added", newField.name)
				}
				result.findings = append(result.findings, contractFinding{
					route: route, severity: severity, reason: reason,
				})
				result.handledChanges[index] = true
			}
		}
	}
	return result
}

func nestedContractFieldName(schema contractSchema, field contractField, change diff.Change) string {
	parent := contractField{}
	for _, candidate := range schema.fields {
		if strings.Contains(candidate.name, ".") || candidate.column >= field.column ||
			candidate.line >= change.OldLine || candidate.line < parent.line {
			continue
		}
		parent = candidate
	}
	if parent.name != "" {
		return parent.name + "." + field.name
	}
	return field.name
}

func schemaFieldForChange(schema contractSchema, field contractField, change diff.Change, added bool) (contractField, bool) {
	line := change.OldLine
	if added {
		line = change.NewLine
	}
	if current, ok := schema.fields[field.name]; ok && (line <= 0 || current.line == 0 || current.line == line) {
		return current, true
	}
	for _, current := range schema.fields {
		if strings.HasSuffix(current.name, "."+field.name) &&
			(line <= 0 || current.line == 0 || current.line == line) {
			return current, true
		}
	}
	return contractField{}, false
}

func schemaFieldNameForChange(schema contractSchema, field contractField, change diff.Change, added bool) string {
	current, ok := schemaFieldForChange(schema, field, change, added)
	if !ok {
		return ""
	}
	return current.name
}

func classifyChangedContractField(direction string, oldField, newField contractField) (string, string) {
	if oldField.typeName != newField.typeName {
		return "breaking", fmt.Sprintf("%s field %q changed type from %s to %s",
			direction, oldField.name, oldField.typeName, newField.typeName)
	}
	if oldField.enumValues != newField.enumValues &&
		(oldField.typeName == "enum" || newField.typeName == "enum") {
		newValues := make(map[string]bool)
		for _, value := range strings.Split(newField.enumValues, ",") {
			newValues[value] = value != ""
		}
		for _, value := range strings.Split(oldField.enumValues, ",") {
			if value != "" && !newValues[value] {
				return "breaking", fmt.Sprintf("%s field %q enum value %q was removed",
					direction, oldField.name, value)
			}
		}
		return "non-breaking", fmt.Sprintf("%s field %q enum value added", direction, oldField.name)
	}
	if oldField.constraints != newField.constraints {
		oldConstraints := make(map[string]bool)
		for _, constraint := range strings.Split(oldField.constraints, ",") {
			oldConstraints[constraint] = constraint != ""
		}
		for _, constraint := range strings.Split(newField.constraints, ",") {
			if constraint != "" && !oldConstraints[constraint] {
				return "breaking", fmt.Sprintf("%s field %q constraint tightened (%s added)",
					direction, oldField.name, constraint)
			}
		}
		return "non-breaking", fmt.Sprintf("%s field %q constraint removed", direction, oldField.name)
	}
	if oldField.optional == newField.optional {
		return "", ""
	}
	if direction == "request" && oldField.optional && !newField.optional {
		return "breaking", fmt.Sprintf("request field %q became required", oldField.name)
	}
	if direction == "response" && !oldField.optional && newField.optional {
		return "breaking", fmt.Sprintf("response field %q became optional", oldField.name)
	}
	return "non-breaking", fmt.Sprintf("%s field %q optionality changed compatibly",
		direction, oldField.name)
}

func schemaContainsChangeLine(schema contractSchema, change diff.Change, added bool) bool {
	line := change.OldLine
	if added {
		line = change.NewLine
	}
	return line > 0 && line >= schema.startLine && line <= schema.endLine+1
}

func routeContractChanges(routes []Route, bindings map[string]routeContract, schemas map[string]contractSchema,
	change diff.File) contractDiffResult {
	result := contractDiffResult{handledChanges: make(map[int]bool)}
	for _, route := range routes {
		one := classifyContractChanges(route, bindings[routeKey(route)], schemas, change)
		result.findings = append(result.findings, one.findings...)
		for index := range one.handledChanges {
			result.handledChanges[index] = true
		}
	}
	sort.Slice(result.findings, func(i, j int) bool {
		if result.findings[i].route.File != result.findings[j].route.File {
			return result.findings[i].route.File < result.findings[j].route.File
		}
		return result.findings[i].reason < result.findings[j].reason
	})
	return result
}
