package diff

import (
	"strings"
	"testing"
)

func TestParseTracksChangedLines(t *testing.T) {
	input := `diff --git a/src/routes.ts b/src/routes.ts
index 1111111..2222222 100644
--- a/src/routes.ts
+++ b/src/routes.ts
@@ -2,3 +2,4 @@
 const app = express();
-app.get("/old", handler);
+app.get("/new", handler);
+app.post("/health", health);
 app.listen(3000);
`

	files, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("got %d files, want 1", len(files))
	}

	file := files[0]
	if file.Path != "src/routes.ts" || file.Status != Modified {
		t.Fatalf("got path/status %q/%q", file.Path, file.Status)
	}
	if len(file.Changes) != 3 {
		t.Fatalf("got %d changes, want 3", len(file.Changes))
	}
	if got := file.Changes[0]; got.Kind != DeletedChange || got.OldLine != 3 || got.Text != `app.get("/old", handler);` {
		t.Fatalf("unexpected deletion: %#v", got)
	}
	if got := file.Changes[1]; got.Kind != AddedChange || got.NewLine != 3 || got.Text != `app.get("/new", handler);` {
		t.Fatalf("unexpected addition: %#v", got)
	}
	if got := file.Changes[2]; got.Kind != AddedChange || got.NewLine != 4 {
		t.Fatalf("unexpected second addition: %#v", got)
	}
}

func TestParseAddedDeletedAndRenamedFiles(t *testing.T) {
	input := `diff --git a/new.js b/new.js
new file mode 100644
--- /dev/null
+++ b/new.js
@@ -0,0 +1 @@
+export const handler = () => {};
diff --git a/old.js b/old.js
deleted file mode 100644
--- a/old.js
+++ /dev/null
@@ -1 +0,0 @@
-export const oldHandler = () => {};
diff --git a/before.js b/after.js
similarity index 100%
rename from before.js
rename to after.js
`

	files, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("got %d files, want 3", len(files))
	}
	if files[0].Status != Added || files[0].Path != "new.js" {
		t.Fatalf("unexpected added file: %#v", files[0])
	}
	if files[1].Status != Deleted || files[1].Path != "old.js" {
		t.Fatalf("unexpected deleted file: %#v", files[1])
	}
	if files[2].Status != Renamed || files[2].OldPath != "before.js" || files[2].Path != "after.js" {
		t.Fatalf("unexpected renamed file: %#v", files[2])
	}
}

func TestParseIgnoresNoNewlineMarkerAndBinaryPayload(t *testing.T) {
	input := `diff --git a/image.png b/image.png
Binary files a/image.png and b/image.png differ
diff --git a/file.js b/file.js
--- a/file.js
+++ b/file.js
@@ -1 +1 @@
-old
\ No newline at end of file
+new
\ No newline at end of file
`

	files, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || len(files[0].Changes) != 0 {
		t.Fatalf("binary diff should have no line changes: %#v", files)
	}
	if len(files[1].Changes) != 2 {
		t.Fatalf("got %d text changes, want 2", len(files[1].Changes))
	}
}
