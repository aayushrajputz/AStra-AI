package analyzer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnalyzeWithCacheInvalidatesChangedFile(t *testing.T) {
	root := t.TempDir()
	cacheDir := filepath.Join(t.TempDir(), "cache")
	sourcePath := filepath.Join(root, "routes.ts")
	writeSource(t, root, "routes.ts", `app.get("/before", handler);`)

	first, err := AnalyzeWithCache(root, cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Routes) != 1 || first.Routes[0].Path != "/before" {
		t.Fatalf("unexpected first report: %#v", first.Routes)
	}

	if err := os.WriteFile(sourcePath, []byte(`app.get("/after", handler);`), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := AnalyzeWithCache(root, cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Routes) != 1 || second.Routes[0].Path != "/after" {
		t.Fatalf("cache returned stale result: %#v", second.Routes)
	}
	cache, err := openParseCache(cacheDir, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(cache.files) != 1 {
		t.Fatalf("cache retained stale file versions: got %d entries, want 1", len(cache.files))
	}
}

func TestAnalyzeWithCacheMatchesUncachedReport(t *testing.T) {
	root := t.TempDir()
	cacheDir := filepath.Join(t.TempDir(), "cache")
	writeSource(t, root, "routes.ts", `const router = express.Router();
router.get("/users", getUsers);
app.use("/api", router);
`)

	want, err := Analyze(root)
	if err != nil {
		t.Fatal(err)
	}
	first, err := AnalyzeWithCache(root, cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := AnalyzeWithCache(root, cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	if !equalRoutes(want.Routes, first.Routes) || !equalRoutes(want.Routes, second.Routes) {
		t.Fatalf("cached reports differ from uncached report:\nwant: %#v\nfirst: %#v\nsecond: %#v",
			want.Routes, first.Routes, second.Routes)
	}
}

func TestParseCachePreservesTokenColumns(t *testing.T) {
	root := t.TempDir()
	cacheDir := filepath.Join(t.TempDir(), "cache")
	content := []byte("interface CreateRequest {\n  email: string;\n}\n")
	cache, err := openParseCache(cacheDir, root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.parse(content); err != nil {
		t.Fatal(err)
	}
	if err := cache.flush(); err != nil {
		t.Fatal(err)
	}

	reopened, err := openParseCache(cacheDir, root)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := reopened.parse(content)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range tokens {
		if token.text == "email" {
			if token.column != 2 {
				t.Fatalf("cached token column = %d, want 2", token.column)
			}
			return
		}
	}
	t.Fatal("email token not found after cache reload")
}

func TestAnalyzeWithCacheReportsCorruptEntry(t *testing.T) {
	root := t.TempDir()
	cacheDir := filepath.Join(t.TempDir(), "cache")
	writeSource(t, root, "routes.ts", `app.get("/users", getUsers);`)
	if _, err := AnalyzeWithCache(root, cacheDir); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(filepath.Join(root, "routes.ts"))
	if err != nil {
		t.Fatal(err)
	}
	cachePath, _, err := cacheEntryPath(cacheDir, root, content)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := AnalyzeWithCache(root, cacheDir); err == nil {
		t.Fatal("expected corrupt cache entry to return an explicit error")
	}
}

func equalRoutes(a, b []Route) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Method != b[i].Method || a[i].Path != b[i].Path ||
			a[i].File != b[i].File || a[i].Line != b[i].Line ||
			a[i].Confidence != b[i].Confidence || len(a[i].Handlers) != len(b[i].Handlers) {
			return false
		}
		for j := range a[i].Handlers {
			if a[i].Handlers[j] != b[i].Handlers[j] {
				return false
			}
		}
	}
	return true
}
