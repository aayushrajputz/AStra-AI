package analyzer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/astra-ai/astra/internal/diff"
)

func TestAnalyzeFindsRoutesAndMountPrefixes(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "routes.ts", `const app = express();
const users = express.Router();
const rootRouter = express.Router();
function getUser(req, res) {}
function createItem(req, res) {}
users.get("/users/:id", getUser);
rootRouter.route("/items").post(createItem);
app.use("/api", users);
app.use("/v1", rootRouter);
app.get("/health", async (req, res) => {});
`)

	report, err := Analyze(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Routes) != 3 {
		t.Fatalf("got %d routes, want 3: %#v", len(report.Routes), report.Routes)
	}
	assertRoute(t, report.Routes, "GET", "/api/users/:id", "getUser")
	assertRoute(t, report.Routes, "POST", "/v1/items", "createItem")
	assertRoute(t, report.Routes, "GET", "/health", "")
	if len(report.Warnings) != 0 {
		t.Fatalf("got unexpected warnings: %#v", report.Warnings)
	}
}

func TestAnalyzeReportsDynamicRoutePath(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.js", "app.get(prefix + \"/users\", handler);\napp.get(`/users/${id}`, handler);\n")

	report, err := Analyze(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Routes) != 0 {
		t.Fatalf("dynamic route should not be indexed: %#v", report.Routes)
	}
	if len(report.Warnings) != 2 || report.Warnings[0].Line != 1 || report.Warnings[1].Line != 2 {
		t.Fatalf("expected line-specific uncertainty warnings, got %#v", report.Warnings)
	}
}

func TestAnalyzeIgnoresRouteTextInCommentsAndStrings(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.js", `// app.get("/comment", handler);
const example = 'app.post("/string", handler)';
app.get("/real", handler);
`)

	report, err := Analyze(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Routes) != 1 || report.Routes[0].Path != "/real" {
		t.Fatalf("unexpected routes: %#v", report.Routes)
	}
}

func TestAnalyzeDiffTracesChangedHelperToRoute(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.ts", `function loadUser() {
	query();
}
function getUser(req, res) {
	loadUser();
}
app.get("/users", getUser);
`)
	changes := []diff.File{{
		Path:   "server.ts",
		Status: diff.Modified,
		Changes: []diff.Change{{
			Kind: diff.AddedChange, NewLine: 2, Text: "query();",
		}},
	}}

	report, err := AnalyzeDiff(root, changes)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.AffectedRoutes) != 1 {
		t.Fatalf("got %d affected routes, want 1: %#v", len(report.AffectedRoutes), report.AffectedRoutes)
	}
	impact := report.AffectedRoutes[0]
	if impact.Route.Path != "/users" || len(impact.Chain) != 2 ||
		impact.Chain[0] != "getUser" || impact.Chain[1] != "loadUser" {
		t.Fatalf("unexpected impact chain: %#v", impact)
	}
}

func TestAnalyzeDiffIgnoresCosmeticChanges(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.js", `function handler() {
	return 1;
}
app.get("/users", handler);
`)
	changes := []diff.File{{
		Path: "server.js", Status: diff.Modified,
		Changes: []diff.Change{
			{Kind: diff.DeletedChange, OldLine: 2, Text: "return 1;"},
			{Kind: diff.AddedChange, NewLine: 2, Text: "  return    1;"},
		},
	}}

	report, err := AnalyzeDiff(root, changes)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.AffectedRoutes) != 0 {
		t.Fatalf("cosmetic-only diff should not affect routes: %#v", report.AffectedRoutes)
	}
}

func TestAnalyzeDiffClassifiesRemovedHandlerAsBreaking(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.js", `app.get("/users", getUser);
`)
	changes := []diff.File{{
		Path: "server.js", Status: diff.Modified,
		Changes: []diff.Change{{
			Kind: diff.DeletedChange, OldLine: 1, Text: "function getUser(req, res) {}",
		}},
	}}

	report, err := AnalyzeDiff(root, changes)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.AffectedRoutes) != 1 {
		t.Fatalf("got %d affected routes, want 1: %#v", len(report.AffectedRoutes), report.AffectedRoutes)
	}
	if report.AffectedRoutes[0].Severity != "breaking" {
		t.Fatalf("severity = %q, want breaking", report.AffectedRoutes[0].Severity)
	}
}

func TestAnalyzeDiffClassifiesSignatureChanges(t *testing.T) {
	tests := []struct {
		name         string
		oldLine      string
		newLine      string
		wantSeverity string
	}{
		{
			name:         "required parameter added",
			oldLine:      "function getUser(req: Request) {}",
			newLine:      "function getUser(req: Request, id: number) {}",
			wantSeverity: "breaking",
		},
		{
			name:         "parameter type changed",
			oldLine:      "function getUser(req: Request, id: string) {}",
			newLine:      "function getUser(req: Request, id: number) {}",
			wantSeverity: "breaking",
		},
		{
			name:         "parameter removed",
			oldLine:      "function getUser(req: Request, id: string) {}",
			newLine:      "function getUser(req: Request) {}",
			wantSeverity: "breaking",
		},
		{
			name:         "optional parameter added",
			oldLine:      "function getUser(req: Request) {}",
			newLine:      "function getUser(req: Request, id?: number) {}",
			wantSeverity: "non-breaking",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "server.ts", test.newLine+"\napp.get(\"/users\", getUser);\n")
			changes := []diff.File{{
				Path: "server.ts", Status: diff.Modified,
				Changes: []diff.Change{
					{Kind: diff.DeletedChange, OldLine: 1, Text: test.oldLine},
					{Kind: diff.AddedChange, NewLine: 1, Text: test.newLine},
				},
			}}

			report, err := AnalyzeDiff(root, changes)
			if err != nil {
				t.Fatal(err)
			}
			if len(report.AffectedRoutes) != 1 {
				t.Fatalf("got %d affected routes, want 1: %#v", len(report.AffectedRoutes), report.AffectedRoutes)
			}
			if got := report.AffectedRoutes[0].Severity; got != test.wantSeverity {
				t.Fatalf("severity = %q, want %q; impact: %#v", got, test.wantSeverity, report.AffectedRoutes[0])
			}
		})
	}
}

func TestAnalyzeDiffClassifiesRequestAndResponseContractFieldChanges(t *testing.T) {
	tests := []struct {
		name         string
		direction    string
		oldField     string
		newField     string
		wantSeverity string
		wantReason   string
	}{
		{
			name: "request field removed", direction: "request",
			oldField: "email: string;", wantSeverity: "breaking", wantReason: `request field "email" was removed`,
		},
		{
			name: "request field retyped", direction: "request",
			oldField: "email: string;", newField: "email: number;",
			wantSeverity: "breaking", wantReason: `request field "email" changed type`,
		},
		{
			name: "new required request field", direction: "request",
			newField: "email: string;", wantSeverity: "breaking", wantReason: `required request field "email" was added`,
		},
		{
			name: "new optional request field", direction: "request",
			newField: "email?: string;", wantSeverity: "non-breaking", wantReason: `optional request field "email" was added`,
		},
		{
			name: "response field removed", direction: "response",
			oldField: "email: string;", wantSeverity: "breaking", wantReason: `response field "email" was removed`,
		},
		{
			name: "response field retyped", direction: "response",
			oldField: "email: string;", newField: "email: number;",
			wantSeverity: "breaking", wantReason: `response field "email" changed type`,
		},
		{
			name: "new response field", direction: "response",
			newField: "email: string;", wantSeverity: "non-breaking", wantReason: `response field "email" was added`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			requestSchema := "interface CreateUserRequest {\n"
			responseSchema := "interface CreateUserResponse {\n"
			if test.direction == "request" {
				if test.newField != "" {
					requestSchema += "  " + test.newField + "\n"
				}
				responseSchema += "  id: string;\n"
			} else {
				requestSchema += "  name: string;\n"
				if test.newField != "" {
					responseSchema += "  " + test.newField + "\n"
				}
			}
			source := requestSchema + "}\n" + responseSchema + `}\n` +
				`function createUser(input: CreateUserRequest): CreateUserResponse { return {} as CreateUserResponse; }
app.post("/users", createUser);
`
			writeSource(t, root, "server.ts", source)

			changes := []diff.Change{}
			fieldLine := 2
			if test.direction == "response" {
				fieldLine = 5
			}
			if test.oldField != "" {
				changes = append(changes, diff.Change{
					Kind: diff.DeletedChange, OldLine: fieldLine, Text: "  " + test.oldField,
				})
			}
			if test.newField != "" {
				changes = append(changes, diff.Change{
					Kind: diff.AddedChange, NewLine: fieldLine, Text: "  " + test.newField,
				})
			}
			report, err := AnalyzeDiff(root, []diff.File{{
				Path: "server.ts", Status: diff.Modified, Changes: changes,
			}})
			if err != nil {
				t.Fatal(err)
			}
			if len(report.AffectedRoutes) != 1 {
				t.Fatalf("got %d affected routes, want 1: %#v", len(report.AffectedRoutes), report.AffectedRoutes)
			}
			impact := report.AffectedRoutes[0]
			if impact.Severity != test.wantSeverity || !strings.Contains(impact.Reason, test.wantReason) {
				t.Fatalf("impact = %#v; want severity %q and reason containing %q",
					impact, test.wantSeverity, test.wantReason)
			}
		})
	}
}

func TestAnalyzeDiffDetectsZodAndClassValidatorContractDrift(t *testing.T) {
	tests := []struct {
		name         string
		source       string
		change       diff.Change
		wantReason   string
		wantSeverity string
	}{
		{
			name: "Zod required request field added",
			source: `const CreateUserSchema = z.object({
  email: z.string(),
});
type CreateUserInput = z.infer<typeof CreateUserSchema>;
type UserResponse = { id: string; };
function createUser(input: CreateUserInput): UserResponse { return {} as UserResponse; }
app.post("/users", createUser);
`,
			change:     diff.Change{Kind: diff.AddedChange, NewLine: 2, Text: "  email: z.string(),"},
			wantReason: `required request field "email" was added`, wantSeverity: "breaking",
		},
		{
			name: "class-validator field removed",
			source: `class CreateUserDto {
  @IsString()
  name: string;
}
class UpdateUserDto {
  @IsString()
  id: string;
}
@Controller("users")
export class UsersController {
  @Post()
  create(@Body() input: CreateUserDto): UpdateUserDto { return input as unknown as UpdateUserDto; }
}
`,
			change:     diff.Change{Kind: diff.DeletedChange, OldLine: 3, Text: "  email: string;"},
			wantReason: `request field "email" was removed`, wantSeverity: "breaking",
		},
		{
			name: "class-validator optional request field added",
			source: `class CreateUserDto {
  @IsOptional()
  email: string;
  @IsString()
  name: string;
}
class UserResponse {
  id: string;
}
@Controller("users")
export class UsersController {
  @Post()
  create(@Body() input: CreateUserDto): UserResponse { return {} as UserResponse; }
}
`,
			change:     diff.Change{Kind: diff.AddedChange, NewLine: 3, Text: "  email: string;"},
			wantReason: `optional request field "email" was added`, wantSeverity: "non-breaking",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "server.ts", test.source)
			report, err := AnalyzeDiff(root, []diff.File{{
				Path: "server.ts", Status: diff.Modified, Changes: []diff.Change{test.change},
			}})
			if err != nil {
				t.Fatal(err)
			}
			if len(report.AffectedRoutes) != 1 {
				t.Fatalf("got %d affected routes, want 1: %#v", len(report.AffectedRoutes), report.AffectedRoutes)
			}
			impact := report.AffectedRoutes[0]
			if impact.Severity != test.wantSeverity || !strings.Contains(impact.Reason, test.wantReason) {
				t.Fatalf("impact = %#v; want severity %q and reason containing %q",
					impact, test.wantSeverity, test.wantReason)
			}
		})
	}
}

func TestAnalyzeDiffClassifiesZodFieldTypeChanges(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.ts", `const CreateUserSchema = z.object({
  email: z.number(),
});
function createUser(input: z.infer<typeof CreateUserSchema>) {}
app.post("/users", createUser);
`)
	report, err := AnalyzeDiff(root, []diff.File{{
		Path: "server.ts", Status: diff.Modified,
		Changes: []diff.Change{
			{Kind: diff.DeletedChange, OldLine: 2, Text: "  email: z.string(),"},
			{Kind: diff.AddedChange, NewLine: 2, Text: "  email: z.number(),"},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.AffectedRoutes) != 1 || report.AffectedRoutes[0].Severity != "breaking" ||
		!strings.Contains(report.AffectedRoutes[0].Reason, "changed type from string to number") {
		t.Fatalf("unexpected Zod type drift result: %#v", report.AffectedRoutes)
	}
}

func TestAnalyzeDiffResolvesImportedRequestAndResponseContracts(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "contracts.ts", `export interface CreateUserRequest {
  email: string;
	  phone: string;
	}
export interface UserResponse {
  id: string;
}
`)
	writeSource(t, root, "server.ts", `import type { CreateUserRequest, UserResponse } from "./contracts";
	const createUser = (input: CreateUserRequest): UserResponse => { return {} as UserResponse; };
app.post("/users", createUser);
`)
	report, err := AnalyzeDiff(root, []diff.File{{
		Path: "contracts.ts", Status: diff.Modified,
		Changes: []diff.Change{{
			Kind: diff.AddedChange, NewLine: 3, Text: "  phone: string;",
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.AffectedRoutes) != 1 {
		t.Fatalf("got %d affected routes, want 1: %#v", len(report.AffectedRoutes), report.AffectedRoutes)
	}
	impact := report.AffectedRoutes[0]
	if impact.Route.Path != "/users" || impact.Severity != "breaking" ||
		!strings.Contains(impact.Reason, `required request field "phone" was added`) {
		t.Fatalf("unexpected imported contract impact: %#v", impact)
	}
}

func TestAnalyzeDiffReadsExpressRequestAndResponseGenerics(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.ts", `interface PathParams { id: string; }
interface UserResponse { id: string; }
interface CreateRequest {
  name: string;
  phone: string;
}
function createUser(req: Request<PathParams, UserResponse, CreateRequest>, res: Response<UserResponse>) {}
app.post("/users", createUser);
`)
	report, err := AnalyzeDiff(root, []diff.File{{
		Path: "server.ts", Status: diff.Modified,
		Changes: []diff.Change{{
			Kind: diff.AddedChange, NewLine: 5, Text: "  phone: string;",
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.AffectedRoutes) != 1 {
		t.Fatalf("got %d affected routes, want 1: %#v", len(report.AffectedRoutes), report.AffectedRoutes)
	}
	if report.AffectedRoutes[0].Severity != "breaking" ||
		!strings.Contains(report.AffectedRoutes[0].Reason, `required request field "phone" was added`) {
		t.Fatalf("unexpected generic request-body impact: %#v", report.AffectedRoutes[0])
	}
}

func TestAnalyzeDiffFlagsUnsupportedNestedContractEditsAsUncertain(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.ts", `interface CreateUserRequest {
  address: {
  };
  name: string;
}
interface UserResponse { id: string; }
function createUser(input: CreateUserRequest): UserResponse { return {} as UserResponse; }
app.post("/users", createUser);
`)
	report, err := AnalyzeDiff(root, []diff.File{{
		Path: "server.ts", Status: diff.Modified,
		Changes: []diff.Change{{
			Kind: diff.DeletedChange, OldLine: 3, Text: "    city: string;",
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.AffectedRoutes) != 1 {
		t.Fatalf("got %d affected routes, want 1 uncertainty impact: %#v", len(report.AffectedRoutes), report.AffectedRoutes)
	}
	if report.AffectedRoutes[0].Severity != "uncertain" {
		t.Fatalf("nested contract edit should remain uncertain, got %#v", report.AffectedRoutes[0])
	}
}

func TestAnalyzeNestJSControllerAndInjectedService(t *testing.T) {
	root := filepath.Join("testdata", "nestjs")
	report, err := Analyze(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Routes) != 4 {
		t.Fatalf("got %d NestJS routes, want 4: %#v", len(report.Routes), report.Routes)
	}
	for _, expected := range []struct {
		method  string
		path    string
		handler string
	}{
		{method: "GET", path: "/users/:id", handler: "UsersController.getUser"},
		{method: "POST", path: "/users", handler: "UsersController.createUser"},
		{method: "PUT", path: "/users/:id", handler: "UsersController.updateUser"},
		{method: "DELETE", path: "/users/:id", handler: "UsersController.deleteUser"},
	} {
		found := false
		for _, route := range report.Routes {
			if route.Method == expected.method && route.Path == expected.path &&
				route.Confidence == "exact" && len(route.Handlers) == 1 &&
				route.Handlers[0] == expected.handler {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing exact NestJS route %s %s handled by %s: %#v",
				expected.method, expected.path, expected.handler, report.Routes)
		}
	}

	changes := []diff.File{{
		Path: "service.ts", Status: diff.Modified,
		Changes: []diff.Change{{Kind: diff.AddedChange, NewLine: 3, Text: "return id.trim();"}},
	}}
	report, err = AnalyzeDiff(root, changes)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.AffectedRoutes) != 1 {
		t.Fatalf("got %d affected routes, want 1: %#v", len(report.AffectedRoutes), report.AffectedRoutes)
	}
	impact := report.AffectedRoutes[0]
	if impact.Confidence != "exact" || len(impact.Chain) != 2 ||
		impact.Chain[0] != "UsersController.getUser" || impact.Chain[1] != "UsersService.findOne" {
		t.Fatalf("unexpected NestJS call graph impact: %#v", impact)
	}
}

func TestAnalyzeExpressRouteChains(t *testing.T) {
	root := filepath.Join("testdata", "express-chain")
	report, err := Analyze(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Routes) != 2 {
		t.Fatalf("got %d chained Express routes, want 2: %#v", len(report.Routes), report.Routes)
	}
	assertRoute(t, report.Routes, "GET", "/api/widgets", "readWidget")
	assertRoute(t, report.Routes, "POST", "/api/widgets", "createWidget")
}

func TestAnalyzeTypeScriptPathsAliasResolvesImportedCall(t *testing.T) {
	root := filepath.Join("testdata", "tsconfig-paths")
	changes := []diff.File{{
		Path: "src/services/users.ts", Status: diff.Modified,
		Changes: []diff.Change{{Kind: diff.AddedChange, NewLine: 3, Text: "return database.find(id);"}},
	}}
	report, err := AnalyzeDiff(root, changes)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.AffectedRoutes) != 1 {
		t.Fatalf("got %d affected routes, want 1: %#v", len(report.AffectedRoutes), report.AffectedRoutes)
	}
	impact := report.AffectedRoutes[0]
	if impact.Route.Path != "/users/:id" || len(impact.Chain) != 2 ||
		impact.Chain[0] != "getUser" || impact.Chain[1] != "fetchUser" {
		t.Fatalf("tsconfig alias did not resolve to the imported export: %#v", impact)
	}
}

func TestAnalyzeFollowsBarrelReexport(t *testing.T) {
	root := filepath.Join("testdata", "barrel-reexports")
	changes := []diff.File{{
		Path: "src/services/users.ts", Status: diff.Modified,
		Changes: []diff.Change{{Kind: diff.AddedChange, NewLine: 3, Text: "return database.find(id);"}},
	}}
	report, err := AnalyzeDiff(root, changes)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.AffectedRoutes) != 1 {
		t.Fatalf("got %d affected routes, want 1: %#v", len(report.AffectedRoutes), report.AffectedRoutes)
	}
	impact := report.AffectedRoutes[0]
	if impact.Route.Path != "/users/:id" || len(impact.Chain) != 2 ||
		impact.Chain[0] != "getUser" || impact.Chain[1] != "fetchUser" {
		t.Fatalf("barrel export did not resolve to the original symbol: %#v", impact)
	}
}

func TestAnalyzeFastifyPluginPrefix(t *testing.T) {
	root := filepath.Join("testdata", "fastify-prefix")
	report, err := Analyze(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Routes) != 1 {
		t.Fatalf("got %d Fastify routes, want 1: %#v", len(report.Routes), report.Routes)
	}
	assertRoute(t, report.Routes, "GET", "/api/users", "listUsers")
}

func TestAnalyzeClassFieldInstanceResolvesMethodEdge(t *testing.T) {
	root := filepath.Join("testdata", "class-field-instance")
	changes := []diff.File{{
		Path: "service.ts", Status: diff.Modified,
		Changes: []diff.Change{{Kind: diff.AddedChange, NewLine: 3, Text: "return database.find(id);"}},
	}}
	report, err := AnalyzeDiff(root, changes)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.AffectedRoutes) != 1 {
		t.Fatalf("got %d affected routes, want 1: %#v", len(report.AffectedRoutes), report.AffectedRoutes)
	}
	impact := report.AffectedRoutes[0]
	if impact.Route.Path != "/accounts/:id" || impact.Confidence != "exact" ||
		len(impact.Chain) != 2 || impact.Chain[0] != "AccountsController.getAccount" ||
		impact.Chain[1] != "AccountsService.findOne" {
		t.Fatalf("class-field instance edge was not resolved: %#v", impact)
	}
}

func assertRoute(t *testing.T, routes []Route, method, path, handler string) {
	t.Helper()
	for _, route := range routes {
		if route.Method == method && route.Path == path {
			if handler == "" {
				if len(route.Handlers) != 0 {
					t.Fatalf("%s %s has unexpected handlers: %#v", method, path, route.Handlers)
				}
			} else if len(route.Handlers) != 1 || route.Handlers[0] != handler {
				t.Fatalf("%s %s has unexpected handlers: %#v", method, path, route.Handlers)
			}
			return
		}
	}
	t.Fatalf("missing route %s %s in %#v", method, path, routes)
}

func writeSource(t *testing.T, root, path, source string) {
	t.Helper()
	fullPath := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
}
