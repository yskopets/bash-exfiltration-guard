// Package ui serves the browser interface.
//
// The compiled assets are embedded so that a plain `go build` produces a
// binary that serves the page with nothing else to install. They can also be
// served from a directory instead, which is what `make dev.run` and the
// container image do -- see Handler.
package ui

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
)

// dist holds whatever `make ui` last wrote.
//
// Only .gitkeep is committed; the built assets are ignored. `all:` matches
// dotfiles, so this embed compiles on a fresh clone with no Node installed
// and the binary still builds -- it just has no page to serve, which Handler
// says out loud rather than answering 404.
//
// The Vite build empties this directory, which would take .gitkeep with it,
// so ui/public/.gitkeep is copied back in on every build. That is what keeps
// `go build` working after `make ui` as well as before it.
//
//go:embed all:dist
var dist embed.FS

// Embedded returns the UI compiled into the binary.
func Embedded() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		// Only reachable if the embed directive above is wrong, which is a
		// build-time mistake rather than a runtime condition.
		panic("ui: embedded assets are malformed: " + err.Error())
	}
	return sub
}

// Built reports whether a UI tree actually contains a page.
func Built(fsys fs.FS) bool {
	if fsys == nil {
		return false
	}
	_, err := fs.Stat(fsys, "index.html")
	return err == nil
}

// Handler serves a UI tree.
//
// Unknown paths fall back to index.html rather than 404, so client-side
// routing works when the page grows it. A request for a missing asset --
// anything under a directory the build produces, or with a file extension --
// still 404s, because silently returning HTML for a missing script is the
// kind of thing that costs an afternoon.
func Handler(fsys fs.FS) http.Handler {
	if !Built(fsys) {
		return http.HandlerFunc(notBuilt)
	}
	files := http.FileServerFS(fsys)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" {
			name = "index.html"
		}
		if _, err := fs.Stat(fsys, name); err == nil {
			files.ServeHTTP(w, r)
			return
		}
		if looksLikeAsset(name) {
			http.NotFound(w, r)
			return
		}
		r = r.Clone(r.Context())
		r.URL.Path = "/"
		files.ServeHTTP(w, r)
	})
}

// looksLikeAsset reports whether a missing path should 404 rather than fall
// back to the page. A dot in the last segment means someone asked for a file.
func looksLikeAsset(name string) bool {
	last := name
	if i := strings.LastIndex(name, "/"); i >= 0 {
		last = name[i+1:]
	}
	return strings.Contains(last, ".")
}

// notBuilt explains a binary built without `make ui`, which is a normal state
// for someone working on the Go side and confusing as a 404.
func notBuilt(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, notBuiltPage)
}

const notBuiltPage = `<!doctype html>
<meta charset="utf-8">
<title>guard - UI not built</title>
<style>
  body { font: 15px/1.6 ui-monospace, SFMono-Regular, Menlo, monospace;
         margin: 3rem auto; max-width: 34rem; padding: 0 1rem; }
  code { background: #f4f4f5; padding: .15em .4em; border-radius: 3px; }
</style>
<h1>UI not built</h1>
<p>This binary was compiled without the browser interface. The API is
   unaffected &mdash; <code>POST /api/v1/assess</code> and
   <code>GET /api/v1/knowledge</code> work as normal.</p>
<p>To build it:</p>
<pre><code>make ui &amp;&amp; make build</code></pre>
<p>Or point a running server at a directory of built assets:</p>
<pre><code>guard serve --ui ./pkg/ui/dist</code></pre>
`
