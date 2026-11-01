package analyzer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const cacheVersion = 2

type cachedManifest struct {
	Version int                       `json:"version"`
	Files   map[string]cachedFileInfo `json:"files"`
}

type cachedFileInfo struct {
	Tokens []cachedToken `json:"tokens"`
}

type cachedToken struct {
	Text   string    `json:"text"`
	Kind   tokenKind `json:"kind"`
	Line   int       `json:"line"`
	Column int       `json:"column"`
	Start  int       `json:"start"`
	End    int       `json:"end"`
}

type parseCache struct {
	path   string
	files  map[string]cachedFileInfo
	active map[string]bool
	dirty  bool
	mu     sync.Mutex
}

func DefaultCacheDir() (string, error) {
	if override := os.Getenv("ASTRA_CACHE_DIR"); override != "" {
		return filepath.Abs(override)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find user home directory for AStra cache: %w", err)
	}
	return filepath.Join(home, ".astra", "cache"), nil
}

func cacheManifestPath(cacheDir, root string) (string, error) {
	if cacheDir == "" {
		return "", fmt.Errorf("cache directory cannot be empty")
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve repository root for cache: %w", err)
	}
	rootHash := sha256.Sum256([]byte(filepath.Clean(absoluteRoot)))
	return filepath.Join(cacheDir, fmt.Sprintf("v%d", cacheVersion),
		hex.EncodeToString(rootHash[:])+".json"), nil
}

func cacheEntryPath(cacheDir, root string, content []byte) (string, string, error) {
	path, err := cacheManifestPath(cacheDir, root)
	if err != nil {
		return "", "", err
	}
	hash := sha256.Sum256(content)
	return path, hex.EncodeToString(hash[:]), nil
}

func openParseCache(cacheDir, root string) (*parseCache, error) {
	path, err := cacheManifestPath(cacheDir, root)
	if err != nil {
		return nil, err
	}
	cache := &parseCache{
		path: path, files: make(map[string]cachedFileInfo), active: make(map[string]bool),
	}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cache, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read cache manifest %s: %w", path, err)
	}
	var manifest cachedManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("decode cache manifest %s: %w", path, err)
	}
	if manifest.Version != cacheVersion || manifest.Files == nil {
		return nil, fmt.Errorf("cache manifest %s has an incompatible version or missing file index", path)
	}
	cache.files = manifest.Files
	return cache, nil
}

func (cache *parseCache) parse(content []byte) ([]token, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	hash := sha256.Sum256(content)
	hashText := hex.EncodeToString(hash[:])
	cache.active[hashText] = true
	if cached, ok := cache.files[hashText]; ok {
		tokens := make([]token, len(cached.Tokens))
		for i, item := range cached.Tokens {
			if item.Kind > punctuationToken || item.Line < 1 || item.Column < 0 || item.Start < 0 ||
				item.End < item.Start || item.End > len(content) {
				return nil, fmt.Errorf("cache manifest %s contains invalid token %d for content %s",
					cache.path, i, hashText)
			}
			tokens[i] = token{
				text: item.Text, kind: item.Kind, line: item.Line, column: item.Column,
				start: item.Start, end: item.End,
			}
		}
		return tokens, nil
	}

	tokens, err := lex(string(content))
	if err != nil {
		return nil, err
	}
	cachedTokens := make([]cachedToken, len(tokens))
	for i, item := range tokens {
		cachedTokens[i] = cachedToken{
			Text: item.text, Kind: item.kind, Line: item.line, Column: item.column,
			Start: item.start, End: item.end,
		}
	}
	cache.files[hashText] = cachedFileInfo{Tokens: cachedTokens}
	cache.dirty = true
	return tokens, nil
}

func (cache *parseCache) flush() error {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	for hash := range cache.files {
		if !cache.active[hash] {
			delete(cache.files, hash)
			cache.dirty = true
		}
	}
	if !cache.dirty {
		return nil
	}
	if err := writeAtomicJSON(cache.path, cachedManifest{
		Version: cacheVersion,
		Files:   cache.files,
	}); err != nil {
		return err
	}
	cache.dirty = false
	return nil
}

func writeAtomicJSON(path string, value any) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create cache directory %s: %w", directory, err)
	}
	file, err := os.CreateTemp(directory, ".astra-cache-*.tmp")
	if err != nil {
		return fmt.Errorf("create cache entry %s: %w", path, err)
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)

	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return fmt.Errorf("set cache entry permissions: %w", err)
	}
	if err := json.NewEncoder(file).Encode(value); err != nil {
		file.Close()
		return fmt.Errorf("encode cache entry %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close cache entry %s: %w", path, err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		if _, statErr := os.Stat(path); statErr == nil {
			return nil
		}
		return fmt.Errorf("install cache entry %s: %w", path, err)
	}
	return nil
}
