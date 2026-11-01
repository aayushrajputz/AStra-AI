package analyzer

import (
	"sort"
)

type nestClass struct {
	name       string
	controller bool
	basePath   string
	open       int
	close      int
	injections map[string]string
}

func analyzeNestFiles(files []sourceFile) ([]Route, map[string][]functionInfo) {
	routes := make([]Route, 0)
	functions := make(map[string][]functionInfo)
	for _, file := range files {
		tokens := file.tokens
		for _, class := range findNestClasses(tokens) {
			methods := findClassMethods(file, class)
			for _, method := range methods {
				if method.name == "constructor" {
					for property, service := range constructorInjections(tokens, method, class) {
						class.injections[property] = service
					}
					continue
				}
				definition := nestMethodInfo(file, class, method)
				functions[definition.name] = append(functions[definition.name], definition)
				if !class.controller || method.routeMethod == "" {
					continue
				}
				routes = append(routes, Route{
					Method: method.routeMethod,
					Path:   joinPath(class.basePath, method.routePath),
					File:   file.path, Line: tokens[method.nameIndex].line,
					Handlers: []string{definition.name}, Confidence: "exact",
				})
			}
		}
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].File != routes[j].File {
			return routes[i].File < routes[j].File
		}
		if routes[i].Line != routes[j].Line {
			return routes[i].Line < routes[j].Line
		}
		return routes[i].Path < routes[j].Path
	})
	return routes, functions
}

func findNestClasses(tokens []token) []nestClass {
	classes := make([]nestClass, 0)
	for i := 0; i+1 < len(tokens); i++ {
		if tokens[i].text != "class" || tokens[i+1].kind != identifierToken {
			continue
		}
		class := nestClass{
			name: tokens[i+1].text, open: -1, close: -1, injections: make(map[string]string),
		}
		for j := i - 1; j >= 0; j-- {
			if tokens[j].text == "}" || tokens[j].text == ";" {
				break
			}
			if tokens[j].text != "@" || j+2 >= len(tokens) ||
				tokens[j+1].text != "Controller" || tokens[j+2].text != "(" {
				continue
			}
			close := matchingToken(tokens, j+2, "(", ")")
			if close < 0 || close+1 >= i {
				break
			}
			class.controller = true
			if close == j+4 && tokens[j+3].kind == stringToken {
				class.basePath = tokens[j+3].text
			}
			break
		}
		for j := i + 2; j < len(tokens); j++ {
			if tokens[j].text == "{" {
				class.open = j
				class.close = matchingToken(tokens, j, "{", "}")
				break
			}
			if tokens[j].text == ";" {
				break
			}
		}
		if class.open >= 0 && class.close > class.open {
			for j := class.open + 1; j+3 < class.close; j++ {
				if tokens[j].kind == identifierToken && tokens[j+1].text == "=" &&
					tokens[j+2].text == "new" && tokens[j+3].kind == identifierToken {
					class.injections[tokens[j].text] = tokens[j+3].text
				}
			}
			classes = append(classes, class)
		}
	}
	return classes
}

type nestMethod struct {
	name        string
	nameIndex   int
	openParen   int
	closeParen  int
	bodyOpen    int
	bodyClose   int
	routeMethod string
	routePath   string
}

func findClassMethods(file sourceFile, class nestClass) []nestMethod {
	methods := make([]nestMethod, 0)
	tokens := file.tokens
	for i := class.open + 1; i < class.close; {
		if tokens[i].text == ";" || tokens[i].text == "}" {
			i++
			continue
		}
		routeMethod, routePath := "", ""
		for i < class.close && tokens[i].text == "@" {
			if i+1 >= class.close {
				break
			}
			decorator := tokens[i+1].text
			if i+2 < class.close && tokens[i+2].text == "(" {
				close := matchingToken(tokens, i+2, "(", ")")
				if close < 0 {
					break
				}
				if method, ok := nestHTTPMethod(decorator); ok {
					routeMethod = method
					if close == i+4 && tokens[i+3].kind == stringToken {
						routePath = tokens[i+3].text
					}
				}
				i = close + 1
			} else {
				i += 2
			}
		}
		for i < class.close && (tokens[i].text == "public" || tokens[i].text == "private" ||
			tokens[i].text == "protected" || tokens[i].text == "async" ||
			tokens[i].text == "static" || tokens[i].text == "readonly") {
			i++
		}
		if i >= class.close || tokens[i].kind != identifierToken || i+1 >= class.close ||
			tokens[i+1].text != "(" {
			i++
			continue
		}
		nameIndex, openParen := i, i+1
		closeParen := matchingToken(tokens, openParen, "(", ")")
		if closeParen < 0 || closeParen >= class.close {
			i = openParen + 1
			continue
		}
		bodyOpen := closeParen + 1
		for bodyOpen < class.close && tokens[bodyOpen].text != "{" && tokens[bodyOpen].text != ";" {
			bodyOpen++
		}
		if bodyOpen >= class.close || tokens[bodyOpen].text != "{" {
			i = closeParen + 1
			continue
		}
		bodyClose := matchingToken(tokens, bodyOpen, "{", "}")
		if bodyClose < 0 || bodyClose > class.close {
			i = bodyOpen + 1
			continue
		}
		methods = append(methods, nestMethod{
			name: tokens[nameIndex].text, nameIndex: nameIndex, openParen: openParen,
			closeParen: closeParen, bodyOpen: bodyOpen, bodyClose: bodyClose,
			routeMethod: routeMethod, routePath: routePath,
		})
		i = bodyClose + 1
	}
	return methods
}

func nestHTTPMethod(decorator string) (string, bool) {
	switch decorator {
	case "Get":
		return "GET", true
	case "Post":
		return "POST", true
	case "Put":
		return "PUT", true
	case "Delete":
		return "DELETE", true
	default:
		return "", false
	}
}

func constructorInjections(tokens []token, constructor nestMethod, class nestClass) map[string]string {
	injections := make(map[string]string)
	for _, parameter := range splitArguments(tokens, constructor.openParen+1, constructor.closeParen) {
		colon := -1
		property := ""
		for i := parameter[0]; i < parameter[1]; i++ {
			if tokens[i].text == ":" {
				colon = i
				break
			}
			if tokens[i].kind == identifierToken && tokens[i].text != "private" &&
				tokens[i].text != "readonly" && tokens[i].text != "public" &&
				tokens[i].text != "protected" && tokens[i].text != "async" {
				property = tokens[i].text
			}
		}
		if colon < 0 || property == "" || colon+1 >= parameter[1] ||
			tokens[colon+1].kind != identifierToken {
			continue
		}
		injections[property] = tokens[colon+1].text
	}
	return injections
}

func nestMethodInfo(file sourceFile, class nestClass, method nestMethod) functionInfo {
	tokens := file.tokens
	info := functionInfo{
		name: class.name + "." + method.name, file: file.path,
		startLine: tokens[method.nameIndex].line, endLine: tokens[method.bodyClose].line,
		bodyStart: method.bodyOpen + 1, bodyEnd: method.bodyClose, imports: file.imports,
	}
	calls := make(map[string]bool)
	for i := info.bodyStart; i+1 < info.bodyEnd; i++ {
		if tokens[i].kind != identifierToken || tokens[i+1].text != "(" || isControlWord(tokens[i].text) {
			continue
		}
		if i >= 4 && tokens[i-1].text == "." && tokens[i-2].kind == identifierToken &&
			tokens[i-3].text == "." && tokens[i-4].text == "this" {
			property, methodName := tokens[i-2].text, tokens[i].text
			if service, ok := class.injections[property]; ok {
				calls[service+"."+methodName] = true
				continue
			}
			calls[class.name+"."+methodName] = true
			continue
		}
		if i >= 2 && tokens[i-1].text == "." && tokens[i-2].text == "this" {
			calls[class.name+"."+tokens[i].text] = true
			continue
		}
		calls[tokens[i].text] = true
	}
	for call := range calls {
		info.calls = append(info.calls, call)
	}
	sort.Strings(info.calls)
	return info
}
