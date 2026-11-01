package analyzer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/astra-ai/astra/internal/diff"
)

type contractField struct {
	name     string
	typeName string
	optional bool
	column   int
}

type contractSchema struct {
	name      string
	file      string
	startLine int
	endLine   int
	fields    map[string]contractField
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
			schemas[file.path+"\x00"+name] = contractSchema{
				name: name, file: file.path,
				startLine: tokens[i+2].line, endLine: tokens[closeObject].line,
				fields: parseContractFields(tokens, i+3, closeObject, true),
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
	fields := make(map[string]contractField)
	for _, member := range splitContractMembers(tokens, start, end) {
		colon := -1
		field := contractField{}
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
		for i := colon + 1; i < member[1]; i++ {
			field.typeName += tokens[i].text
			if tokens[i].text == "?" && i+1 < member[1] && tokens[i+1].text == "." &&
				i+2 < member[1] && tokens[i+2].text == "optional" {
				field.optional = true
			}
		}
		if zod {
			field.typeName = zodFieldType(tokens, colon+1, member[1])
		}
		if field.name != "" && field.typeName != "" {
			fields[field.name] = field
		}
	}
	return fields
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
		expectedExpression := ""
		switch tokens[i+2].text {
		case "string":
			base, expectedExpression = "string", "z.string()"
		case "number":
			base, expectedExpression = "number", "z.number()"
		case "boolean":
			base, expectedExpression = "boolean", "z.boolean()"
		case "date":
			base, expectedExpression = "Date", "z.date()"
		case "array":
			for j := i + 3; j+2 < end; j++ {
				if tokens[j].text != "z" || tokens[j+1].text != "." {
					continue
				}
				switch tokens[j+2].text {
				case "string", "number", "boolean", "date":
					elementType := zodPrimitiveType(tokens[j+2].text)
					base = "array<" + elementType + ">"
					expectedExpression = "z.array(z." + strings.ToLower(elementType) + "())"
				}
				if base != "" {
					break
				}
			}
		case "object":
			base, expectedExpression = "object", "z.object()"
		case "enum", "literal", "union", "record", "tuple":
			return "zod:" + normalizedZodExpression(tokens, start, end)
		}
		if base != "" {
			expression := normalizedZodExpression(tokens, start, end)
			if expression == expectedExpression {
				return base
			}
			return base + "|" + expression
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
	for _, file := range files {
		fileByPath[file.path] = file
	}
	bindings := make(map[string]routeContract)
	for _, route := range routes {
		file, ok := fileByPath[route.File]
		if !ok {
			continue
		}
		binding := routeContract{}
		for _, handler := range route.Handlers {
			requestType, responseType := handlerContractTypes(file, handler)
			if name := findSchemaReference(requestType, file, schemas); name != "" {
				binding.request = appendUniqueContractRef(binding.request, resolveSchemaReference(name, file, schemas))
			}
			if name := findSchemaReference(responseType, file, schemas); name != "" {
				binding.response = appendUniqueContractRef(binding.response, resolveSchemaReference(name, file, schemas))
			}
		}
		bindings[routeKey(route)] = binding
	}
	return bindings
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
		end := colon + 1
		for end < len(tokens) && tokens[end].text != ";" && tokens[end].text != "," &&
			tokens[end].text != "=" {
			if tokens[end].text == "." && end+1 < len(tokens) && tokens[end+1].text == "optional" {
				field.optional = true
			}
			field.typeName += tokens[end].text
			end++
		}
		if field.typeName == "" {
			return contractField{}, false
		}
		if strings.Contains(field.typeName, "z.") {
			field.typeName = changedZodType(field.typeName)
			field.optional = field.optional || strings.Contains(source, ".optional")
		}
		return field, true
	}
	return contractField{}, false
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
					if _, fieldExists := schema.fields[oldField.name]; !fieldExists {
						continue
					}
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
				if _, exists := schema.fields[oldField.name]; exists {
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
					reason: fmt.Sprintf("%s field %q was removed", direction.label, oldField.name),
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
				current, exists := schema.fields[newField.name]
				if !exists || current.typeName != newField.typeName {
					continue
				}
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

func classifyChangedContractField(direction string, oldField, newField contractField) (string, string) {
	if oldField.typeName != newField.typeName {
		return "breaking", fmt.Sprintf("%s field %q changed type from %s to %s",
			direction, oldField.name, oldField.typeName, newField.typeName)
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
