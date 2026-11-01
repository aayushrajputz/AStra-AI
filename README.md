# AStra

AStra is a local Go CLI for exploring which Express-style HTTP routes may be
affected by a code change. Analysis is deterministic and offline; the current
TypeScript/JavaScript scanner is a lightweight pure-Go lexer, not a full
language parser. Findings are therefore labeled heuristic or uncertain.

## Requirements

- Go 1.24 or newer
- Git

The project has no third-party Go dependencies. It does not execute repository
source code or make network requests. Parsed tokens, including literal text
tokens, are cached locally under `~/.astra/cache` (the Windows equivalent is
under the user's home directory); set `ASTRA_CACHE_DIR` to override the cache
location.

### Install a release

Prebuilt binaries are published for Windows, Linux, and macOS on `amd64` and
`arm64`. Download the matching executable and `checksums.txt` from the
[latest GitHub Release](https://github.com/aayushrajputz/AStra-AI/releases/latest).
For Windows x64, the asset is named `astra_<version>_windows_amd64.exe`.
Put `astra.exe` in a directory on `PATH`, then run:

```powershell
astra check
astra list-routes
astra mcp
```

In PowerShell, you can install the Windows x64 binary for the current user
(replace the version if a newer release is available):

```powershell
$installDir = Join-Path $HOME ".astra\bin"
New-Item -ItemType Directory -Force $installDir | Out-Null
Invoke-WebRequest `
  "https://github.com/aayushrajputz/AStra-AI/releases/download/v0.2.5/astra_0.2.5_windows_amd64.exe" `
  -OutFile (Join-Path $installDir "astra.exe")
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (($userPath -split ";") -notcontains $installDir) {
  [Environment]::SetEnvironmentVariable("Path", "$userPath;$installDir", "User")
}
$env:Path = "$installDir;$env:Path"
astra --help
```

Reopen PowerShell after installation for the persistent `PATH` update to take
effect in new terminals. Releases are created from `v*` tags by GitHub Actions;
each binary asset is accompanied by a SHA-256 checksum in `checksums.txt`.

The npm launcher is published as `@trietitan/astra-ai` (the unscoped
`astra-ai` name is owned by an unrelated npm package). Users can install it
globally or run it with `npx`:

```powershell
npm install -g @trietitan/astra-ai
astra --help
astra-ai list-routes
npx @trietitan/astra-ai check
```

Publishing new versions requires an npm account that owns the `@trietitan`
scope and a GitHub Actions secret named `NPM_TOKEN`. To test the launcher
locally without publishing:

```powershell
npm test --prefix npm/astra-ai
```

To publish an already-created GitHub release to npm, add the `NPM_TOKEN`
repository secret, then run the **Publish npm package** workflow from the
Actions tab and enter the release version without its `v` prefix (for example,
`0.2.5`) and the npm account scope without `@` (for example, `trietitan`). This
publishes the package from that release tag without rebuilding or replacing
its GitHub Release assets.

## Use

Run commands from a Git working tree:

```powershell
go run ./cmd/astra check
go run ./cmd/astra check --staged
go run ./cmd/astra check --base main
go run ./cmd/astra check --json
go run ./cmd/astra list-routes
go run ./cmd/astra bench
go run ./cmd/astra install-hook
```

By default, `check` analyzes the diff between `HEAD` and the working tree,
including staged and unstaged changes. `--staged` analyzes only the index;
`--base` compares the working tree against the named Git ref. The pre-commit
hook runs `astra check --staged --gate`; install the `astra` binary on `PATH`
before using that hook.

`check --json` emits a structured report containing indexed routes, affected
routes, call chains where the scanner can establish them, confidence/severity,
and warnings. `check --gate --json` additionally applies `.astrarc.json` and
returns a `status`, `violations`, `needs_review`, and active waivers; gate
failures exit with code 1 and tool errors exit with code 2.

The optional `.astrarc.json` policy supports ignored Git paths, display labels
for finding severities, and the gate threshold:

```json
{
  "ignored_paths": ["docs/**", "**/*.generated.ts"],
  "severity_rules": {
    "breaking": "critical",
    "potential": "warning",
    "uncertain": "notice"
  },
  "fail_on": "unresolved-breaking",
  "ignore_paths": ["docs/**"],
  "route_severity": {
    "POST /transfer": "any-breaking"
  },
  "allow_heuristic_failures": false
}
```

`ignored_paths`/`ignore_paths` uses repository-relative `/` paths and `*`, `?`,
and `**` wildcards. The `fail_on` modes are `unresolved-breaking` (default),
`any-breaking`, and `never`; the legacy list of severities is also accepted.
`route_severity` overrides the mode for an exact `"METHOD /path"` route.
Heuristic findings are reported as `needs_review`, not failed, unless
`allow_heuristic_failures` is explicitly enabled. `severity_rules` changes
display labels, not classification.

### Making it enforceable

The checked-in GitHub Actions workflow runs AStra on pull requests and reports
the route impacts, resolution, call chains, incompatible callers, and active
waivers in one updatable PR comment. The workflow job itself is the status
check: in repository settings, add its **AStra route impact** check as a
required status check for the protected branch. Protect the branch from direct
pushes (including administrator bypass where your policy permits) so every
change must pass the pull-request check. The local pre-commit hook is a fast
early warning only; `git commit --no-verify` bypasses it, so CI is the
authoritative gate.

Waivers live in `.astra-waivers.json` and must identify one symbol or route,
explain the reason, name an owner, and set an expiry date:

```json
{
  "waivers": [
    {
      "symbol": "TransferService.Move",
      "reason": "Keep compatibility during the client migration",
      "owner": "payments-team",
      "expires": "2099-12-31"
    }
  ]
}
```

Expired waivers fail the gate and active waivers are included in the report.
AStra is static analysis, not a proof of runtime behavior: dynamic code,
dependency injection and framework wrappers it does not recognize, and
external clients are not fully modeled. Review `needs_review` findings and
warnings, and do not treat an unreported route as proof that no impact exists.

## Optional AI explanations (M9)

AI explanations are off by default. To opt in, select a provider and model;
credentials are read only from the provider's environment variable:

```powershell
$env:OPENAI_API_KEY = "..."
astra check --ai-provider openai-compatible --ai-model <model>

$env:ANTHROPIC_API_KEY = "..."
astra check --ai-provider anthropic --ai-model <model>
```

Only changed function signatures and deterministic route-impact metadata are
sent; function bodies and full diffs are not included. Before sending anything,
inspect the exact request with `--ai-dry-run`. The preview redacts credentials
and makes no network request. Use `--ai-endpoint` only when intentionally
overriding the provider endpoint. Responses must match the strict JSON schema
and may explain only routes already found by the deterministic analyzer.
Explanations are separate from route findings and gate status; API, decoding,
or validation errors are reported without changing those deterministic
results. Successful explanations are cached under `~/.astra/ai-cache`.

M9 verification covers opt-in behavior, credential redaction and no-network
dry runs, provider-specific API-key environment variables, strict response
validation, route allowlisting, and cache hits. The full Go tests and `go vet`
pass. The synthetic M1 corpus remains at **60.0% precision**, **75.0% recall**,
and **33.3% false-positive rate**; the 3,000-file warm-cache measurement was
**127.9 ms/op**, below the 300 ms target (local runs vary).

## Current analysis coverage

- Express-style `app.get(...)`, `router.post(...)`, and related HTTP methods
- `router.route("/path").get(...).post(...)` method chains
- Literal mount prefixes passed to `.use("/prefix", router)`
- Fastify `register(plugin, { prefix })` for named function plugins with literal
  prefixes
- NestJS `@Controller` and `@Get`, `@Post`, `@Put`, `@Delete` decorators, with
  constructor property injection
- Syntactic class-field instances such as `private service = new Service()` and
  `this.service.method()` call edges
- `tsconfig.json` `baseUrl`/`paths` aliases for named imports, including named
  barrel re-exports
- Named function and block-bodied arrow-function call chains
- Removed route declarations, removed named route handlers, and detected
  required/removed/retyped parameters are reported as breaking
- Added optional (`?`) and defaulted (`= value`) function parameters are
  reported as non-breaking; other reachable changes are reported as potential
- Request/response contract drift is detected for named TypeScript interfaces
  and object type aliases, DTO classes, and Zod `z.object` request schemas,
  including common `body`/`query`/`params` envelopes
- Top-level non-function `const`/`let`/`var`, type aliases, interfaces, and
  enums are indexed as symbols; route middleware arguments and composed
  initializers can connect those symbols to affected routes
- Zod request field additions/removals, primitive type changes, optional/default
  additions, enum value removals, and common constraint additions are classified;
  constraint tightening is heuristic
- `astra check --debug` (or `ASTRA_DEBUG=1`) prints changed-range attribution,
  route arguments, symbol references, and resolved named imports to stderr
- Whitespace- and comment-only edits are filtered from impact findings
- Dynamic paths on recognized HTTP route registrations produce line-specific
  warnings instead of guessed routes; unrelated `.get()` calls and calls with
  fewer than two arguments are ignored

The analyzer remains a lightweight pure-Go lexer, not a TypeScript compiler or
Tree-sitter parser. It recognizes common router names and handler-shaped
callbacks to distinguish route registrations from ordinary methods such as
`redis.get()` and `Map.get()`. `exact` is limited to the supported syntactic
NestJS edges;
other route and call-graph findings remain heuristic (`~`). The module resolver
reads only the repository-root `tsconfig.json`; it does not follow `extends`,
project references, package exports, namespace imports, or arbitrary TypeScript
compiler options. Relative modules, named/default imports, named re-exports,
and `export *` chains are resolved when the target is statically available.
Dynamic imports, schemas assembled in loops or runtime-generated code, unresolved
spreads, `.refine()`/`.transform()`/`.superRefine()`, and Zod `.pick()`/`.omit()`
or complex composition are reported for review rather than guessed. Runtime-
generated routes and nonliteral paths are not statically traced. Unattributed
source changes are explicitly listed; only routes importing the changed module
are marked uncertain. Fastify prefix handling currently supports literal prefixes
registered against named function plugins. NestJS handling supports named
classes with literal controller/route paths and constructor parameter
properties; custom decorators, inherited controllers, guard/interceptor
behavior, and container-driven injection are not modeled. Class-field receiver
resolution covers simple `property = new Class()` declarations, not reassignment,
factory functions, generic inference, or arbitrary object flow. Signature
classification remains limited to simple, single-line function declarations
and parenthesized arrow functions. Module-level references are supported for
indexed declarations, but dynamic JavaScript scope and arbitrary value flow are
not modeled; review uncertainty warnings before using the tool as a gate.

### Go route analysis (M8)

Go files are parsed with the Go standard library; AStra does not download Go
modules, type-check the project, or execute its source. The current supported
route patterns are Gin `gin.New`/`gin.Default` with literal `Group` prefixes,
Chi `chi.NewRouter` with nested literal `Route` callbacks, and Echo `echo.New`
with literal `Group` prefixes. Their standard HTTP verb registrations are
indexed when the handler is a named function, package-qualified function, or
a method expression on a recognizable struct value.
Package-qualified calls are followed across packages inside the module named
by the repository's `go.mod`. Added, removed, or retyped parameters on
single-line Go function signatures are classified by the existing breaking
change rules.

Request schemas are extracted from tagged Go structs used by recognized
`Bind`/`Decode` calls in route handlers. The `json` tag supplies the field
name; `binding:"required"` or `validate:"required"` marks a request field
required, while `omitempty`/`omitzero` indicates optional output. Changes to
removed or retyped fields, and newly required request fields, use the existing
contract drift classifications (`~`). Go route and call-graph results remain
heuristic (`~`). Dynamic routes, routes registered through unrecognized
wrappers or interfaces, external-package resolution, embedded/inherited
handlers, arbitrary dependency injection, and complete Go type-flow are not
modeled; treat unsupported constructs as uncertainty rather than proof of no
impact.

#### M8 verification

The fixture suite covers Gin groups, nested Chi routes, Echo groups,
cross-package handler-to-service call chains, a breaking Go function signature
change, and a removed JSON-tagged request field. All three frameworks are
represented by dedicated analyzer fixtures. The synthetic commit corpus now
also includes a Gin service-signature commit:

| Corpus result | TP | FP | FN | TN | Precision | Recall | False-positive rate |
|---|---:|---:|---:|---:|---:|---:|---:|
| Go Gin signature case | 1 | 0 | 0 | 1 | 100.0% | 100.0% | 0.0% |
| Combined six-case corpus | 3 | 1 | 1 | 5 | 75.0% | 75.0% | 16.7% |
| Original five TypeScript cases | 2 | 1 | 1 | 4 | 66.7% | 66.7% | 20.0% |

The updated module-level fallback no longer counts unrelated documentation
edits as route impacts; this improves the synthetic corpus figures but does not
change its status as a smoke benchmark rather than a real-world accuracy claim.
The 3,000-file warm-cache target remains below 300 ms/op; local measurements
vary and are not a CI guarantee.

Contract analysis associates a route handler's first typed parameter (or the
body type in an Express `Request<Params, ResponseBody, RequestBody>`) with its
request schema. A handler return type or `Response<ResponseBody>` parameter
associates the response schema. DTO properties, `?` optional markers, and
`@IsOptional()` are recognized; simple Zod `z.object` fields and
`z.infer<typeof Schema>` aliases are supported. Schema references may be named
imports resolved by the existing module resolver. Removed or retyped request
and response fields are breaking; a newly required request field is breaking;
an optional request field or new response field is non-breaking. Schema
findings are labeled heuristic (`~`). Nested/conditional/mapped types, Zod
compositions and refinements, arbitrary validator decorators, interface
inheritance, response data-flow inference, and framework-specific request
binding beyond the supported signatures are not modeled. Unsupported schema
edits remain subject to the analyzer's existing uncertainty behavior.

The initial M1 benchmark harness is in [`bench`](./bench). It creates temporary
Git repositories from the checked-in before/after fixtures, makes a baseline
commit and a change commit for each case, then evaluates the resulting commit
diff with the current analyzer. Run it with `go run ./cmd/astra bench` or
`go test ./bench -v`.

The current corpus is a small, curated **synthetic** sample, not the roadmap's
real open-source commit corpus. Its measurements are a reproducible smoke
baseline only and must not be presented as real-world accuracy. Precision treats
every reported affected route as an alert; a manually labeled non-breaking
route alert therefore counts as a false positive. Recall is the share of
manually labeled breaking routes that were reported. The false-positive rate is
measured over the explicitly listed known route universe. Gold labels and
uncertainty cases are in [`bench/testdata/corpus.json`](./bench/testdata/corpus.json).

### Initial synthetic baseline

Measured 2026-11-01 on five generated Git commit pairs (controller signature,
middleware behavior, non-breaking controller change, documentation-only change,
and dynamic route):

| Metric | Baseline |
|---|---:|
| Precision | 50.0% (2 TP / 4 reported routes) |
| Recall | 66.7% (2 TP / 3 breaking routes) |
| False-positive rate | 40.0% (2 FP / 5 actual negatives) |
| Counts | TP 2, FP 2, FN 1, TN 3 |

This tiny synthetic corpus is not representative of real-world accuracy. It
does expose two concrete baseline issues: a non-breaking controller edit and a
documentation-only edit each report a false-positive route, and the changed
dependency of a dynamic route is missed while the route scanner emits an
uncertainty warning (`⚠`). Heuristic route impacts are marked `~`.

## M3 framework-depth gate

The six M3 fixture-backed additions pass. The synthetic M1 corpus is unchanged:
precision **50.0%**, recall **66.7%**, false-positive rate **40.0%**. Thus M3
recall stayed at baseline (no M1 case regressed), but it did not demonstrate an
accuracy improvement; the synthetic corpus contains no NestJS, Fastify, or
TypeScript alias benchmark commits. The roadmap's real-open-source benchmark
gate is still outstanding.

## M5 contract-drift gate

The fixture-backed classification table passes for removed and retyped request
fields, newly required and optional request fields, and removed, retyped, and
added response fields. Additional analyzer tests cover named interfaces/type
aliases, imported schemas, Zod schemas and `z.infer` aliases, class-validator
DTOs including `@IsOptional()`, and Express request/response generics. Schema
findings flow through the existing `affected_routes` report consumed by the
CLI and MCP tools; their confidence remains heuristic.

The M1 synthetic benchmark is unchanged after M5: precision **50.0%**, recall
**66.7%**, and false-positive rate **40.0%**. The corpus contains no contract
drift commits, so this is a no-regression check, not evidence that contract
analysis improves real-world accuracy. M5's decidable classification gate is
the fixture-backed table above.

## M6 GitHub Actions

The composite action at
[`action.yml`](./.github/actions/astra-check/action.yml)
builds the checked-out AStra Go source, runs `astra check --base REF --json
--gate`, upserts one route-impact comment on pull requests, and fails the job
when the configured gate fails. The sample workflow is
[`astra.yml`](./.github/workflows/astra.yml). It checks out
full history and grants only `contents: read` and `pull-requests: write`.
When reusing the action, provide a base commit/ref available locally and a
token with pull-request comment write permission. This M6 action builds from
source; release-asset downloads are deferred until the M7 packaging milestone.

## Parse cache (M2)

The CLI stores a per-repository JSON manifest under `~/.astra/cache`. Parsed
file tokens are reused by SHA-256 content hash; files are still read and hashed
on each run, while unchanged files skip lexing. The call graph and routes are
rebuilt from the current file set on every analysis. Cache entries are pruned
when their content is no longer present in the repository. Writes are atomic,
and cache read/format errors are returned explicitly rather than silently
ignored. Set `ASTRA_CACHE_DIR` to isolate or relocate the cache.

The 3,000-file warm-cache benchmark is:

```powershell
go test ./internal/analyzer -run '^$' -bench '^BenchmarkAnalyzeWarmCache3000Files$' -benchtime=1x -benchmem
```

On the Windows development machine (AMD Ryzen 5 5600H), the original M2 run was
**168.8 ms/op**. After M3, the same three-iteration warm benchmark measured
**118.5 ms/op** (cache populated before timing), about **29.8% faster** than that
recorded M2 run and below the 300 ms target. This is a local benchmark
measurement, not a CI guarantee; run it on the target machine to compare
performance.
The post-M5 three-iteration verification measured **126.8 ms/op**, also below
the target.

## MCP server (M4)

Start AStra from a Git working tree and configure your MCP client to launch
`astra mcp` with that repository as its working directory. The server uses
newline-delimited JSON-RPC over stdio and requires no MCP SDK or network access.
For example, after building the `astra` binary, an MCP client configuration can
launch the command with `"command": "astra"` and `"args": ["mcp"]`.

For VS Code workspace testing, `.vscode/mcp.json` starts the local server with
`go run ./cmd/astra mcp` and uses the opened workspace as its repository root.
Open this repository in VS Code, start/restart the `astra` server from the MCP
Servers view, and ask the agent to call `astra_list_routes` or
`astra_check_diff`. Go and Git must be installed. For a different application,
use that application's repository as the server working directory and point
the launch command at the AStra binary or source checkout.

The read-only tools are:

- `astra_check_diff`: analyze `staged`, `working`, or `base` Git changes.
- `astra_blast_radius`: find routes reachable from a repository file's symbol
  or positive source line.
- `astra_list_routes`: list detected routes, methods, files, and handlers.
- `astra_explain_route`: show the call chain for an HTTP method and path.
- `astra_gate`: evaluate the working diff against `.astrarc.json`.

The `astra://report/latest` resource exposes the latest report generated in
that server process. Tool responses include structured JSON and text content;
analysis warnings and heuristic confidence labels are retained. Git is invoked
only for read-only diff and repository-root queries. File arguments to
`astra_blast_radius` must resolve inside the Git repository root, including
after symlink resolution. Requests and results are each limited to 1 MiB.

The gate defaults to failing only on `breaking` impacts. A repository can
configure `fail-on` as a string or list in `.astrarc.json`, for example
`{"fail-on":["breaking","potential"]}`; the equivalent `fail_on` key is also
accepted. An explicit empty list disables severity failures.

## Test

```powershell
go test ./...
go vet ./...
```
