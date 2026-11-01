package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkAnalyzeWarmCache3000Files(b *testing.B) {
	root := b.TempDir()
	cacheDir := filepath.Join(b.TempDir(), "cache")
	for i := 0; i < 3000; i++ {
		path := filepath.Join(root, "src", fmt.Sprintf("handler-%04d.ts", i))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			b.Fatal(err)
		}
		source := fmt.Sprintf("function handler%d(req, res) { res.send(%q); }\napp.get(%q, handler%d);\n",
			i, "ok", fmt.Sprintf("/items/%d", i), i)
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			b.Fatal(err)
		}
	}
	if _, err := AnalyzeWithCache(root, cacheDir); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := AnalyzeWithCache(root, cacheDir); err != nil {
			b.Fatal(err)
		}
	}
}
