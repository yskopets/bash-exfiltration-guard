package ui

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func built() fs.FS {
	return fstest.MapFS{
		"index.html":            {Data: []byte(`<!doctype html><title>guard</title><div id=root>`)},
		"assets/app-abc123.js":  {Data: []byte(`console.log(1)`)},
		"assets/app-abc123.css": {Data: []byte(`body{}`)},
	}
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestServesThePageAndItsAssets(t *testing.T) {
	h := Handler(built())

	if rec := get(t, h, "/"); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "<div id=root>") {
		t.Errorf("/ = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := get(t, h, "/assets/app-abc123.js"); rec.Code != http.StatusOK {
		t.Errorf("asset = %d", rec.Code)
	}
}

// Unknown paths fall back to the page, so client-side routing works when the
// UI grows it.
func TestUnknownPathFallsBackToThePage(t *testing.T) {
	rec := get(t, Handler(built()), "/some/future/route")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<div id=root>") {
		t.Errorf("fallback = %d: %s", rec.Code, rec.Body.String())
	}
}

// A missing asset must not get HTML back. Serving a page where a script was
// requested turns a build mistake into a mystery.
func TestMissingAssetIsNotFound(t *testing.T) {
	for _, path := range []string{"/assets/gone.js", "/favicon.ico", "/nested/thing.css"} {
		if rec := get(t, Handler(built()), path); rec.Code != http.StatusNotFound {
			t.Errorf("%s = %d, want 404", path, rec.Code)
		}
	}
}

// A binary built without `make ui` is a normal state while working on the Go
// side, and a 404 would look like a bug.
func TestNotBuiltExplainsItself(t *testing.T) {
	h := Handler(fstest.MapFS{})

	rec := get(t, h, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("/ = %d, want 200", rec.Code)
	}
	for _, want := range []string{"UI not built", "make ui", "/api/v1/assess"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("page does not mention %q:\n%s", want, rec.Body.String())
		}
	}
	if rec := get(t, h, "/elsewhere"); rec.Code != http.StatusNotFound {
		t.Errorf("/elsewhere = %d, want 404", rec.Code)
	}
}

func TestBuilt(t *testing.T) {
	if Built(nil) || Built(fstest.MapFS{}) {
		t.Errorf("an empty tree reported as built")
	}
	if !Built(built()) {
		t.Errorf("a tree with index.html reported as not built")
	}
	// The embedded tree compiles either way; whether it has a page depends on
	// whether `make ui` ran, so this only asserts it does not explode.
	_ = Built(Embedded())
}
