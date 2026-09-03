package server

// The HTTP API.
//
// This server ANALYZES commands. It never executes one, never spawns a shell,
// and never touches the filesystem paths a command mentions. The only thing it
// does with the string it is handed is parse it and walk the syntax tree.
// Worth saying plainly, because "POST a shell command to a server" reads
// alarming otherwise.
//
// It is an unauthenticated local sidecar. The default bind is loopback and it
// should stay there; there is no authentication, and adding some belongs with
// a deployment story rather than with the API shape.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"guard/pkg/analyze"
	"guard/pkg/api"
	"guard/pkg/knowledge"
	"guard/pkg/ui"
)

// maxBodyBytes caps a request. The largest command in a corpus of 172,661
// real CI invocations was 43 KB, so a megabyte is generous by more than an
// order of magnitude while still refusing anything absurd.
const maxBodyBytes = 1 << 20

// Server answers assessment requests against one knowledge base.
//
// The base is loaded once, before the server starts, and is read-only
// thereafter. Each request builds its own Analyzer, so nothing is shared
// mutably between them -- which is asserted by a test under -race rather than
// assumed.
type Server struct {
	kb  *knowledge.Base
	ui  fs.FS
	log *log.Logger
}

// NewServer builds a server.
//
// uiFS is where the browser interface is served from: a directory when the
// caller passed --ui or GUARD_UI, and the assets compiled into the binary
// when it is nil.
func NewServer(kb *knowledge.Base, uiFS fs.FS, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	if uiFS == nil {
		uiFS = ui.Embedded()
	}
	return &Server{kb: kb, ui: uiFS, log: logger}
}

// Routes are under /api/v1: /api names the machine-readable surface, leaving
// the rest of the path space free for anything a person is meant to open, and
// /v1 is where a breaking change to the response shape would go.
const apiPrefix = "/api/v1"

// Handler builds the routing table.
//
// There is no health endpoint. GET /api/v1/knowledge is cheap, needs no
// analysis, and answers "is it up?" and "which policy is it running?"
// together, which is strictly more than a bare 200 would say.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(apiPrefix+"/assess", s.handleAssess)
	mux.HandleFunc(apiPrefix+"/knowledge", s.handleKnowledge)

	// "/" is the catch-all pattern, and ServeMux prefers the more specific
	// one, so the API routes above still win over the page.
	mux.Handle("/", ui.Handler(s.ui))

	return s.recoverPanics(s.logRequests(mux))
}

// ------------------------------------------------------------- endpoints

type assessRequest struct {
	Command string `json:"command"`
}

func (s *Server) handleAssess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("command too large; the limit is %d bytes", maxBodyBytes))
			return
		}
		writeError(w, http.StatusBadRequest, "cannot read request body")
		return
	}

	var req assessRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "body must be JSON: "+err.Error())
		return
	}
	if req.Command == "" {
		writeError(w, http.StatusBadRequest, `"command" is required and must not be empty`)
		return
	}

	writeJSON(w, http.StatusOK, s.Assess(req.Command))
}

// Assess runs one command through the analyzer. Exported so the CLI shares
// exactly this path, and so tests can exercise it without HTTP.
func (s *Server) Assess(command string) api.Assessment {
	a, err := analyze.Analyze(command, s.kb)
	if err != nil {
		// An unparsable command is a verdict, not a transport error: the data
		// flow is unknown, and unknown is never an allow. Returning 4xx here
		// would invite callers to read it as "retry" rather than "refused".
		return api.UnparsableAssessment(command, s.kb, err)
	}
	verdict, reasons := a.Decide()
	return api.NewAssessment(command, a, verdict, reasons)
}

type knowledgeResponse struct {
	Source      string `json:"source"`
	Summary     string `json:"summary"`
	Commands    int    `json:"commands"`
	Subcommands int    `json:"subcommands"`
}

func (s *Server) handleKnowledge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}
	commands, subcommands := s.kb.Counts()
	writeJSON(w, http.StatusOK, knowledgeResponse{
		Source:      s.kb.Source,
		Summary:     s.kb.Summary(),
		Commands:    commands,
		Subcommands: subcommands,
	})
}

// ------------------------------------------------------------ middleware

// recoverPanics keeps one bad command from taking the process down. The
// analyzer handled 129,915 real commands without panicking, but a long-lived
// server must not stake its life on that continuing to hold.
func (s *Server) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				s.log.Printf("panic handling %s %s: %v", r.Method, r.URL.Path, v)
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status  int
	verdict string
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.log.Printf("%s %s %d %s%s", r.Method, r.URL.Path, rec.status,
			time.Since(start).Round(time.Microsecond), verdictSuffix(rec.verdict))
	})
}

func verdictSuffix(v string) string {
	if v == "" {
		return ""
	}
	return " " + v
}

// ---------------------------------------------------------------- serving

// ListenAndServe runs until the context is cancelled or a signal arrives,
// then drains in-flight requests before returning.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	s.log.Printf("guard listening on %s, knowledge base %s", ln.Addr(), s.kb.Source)

	errs := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- err
			return
		}
		errs <- nil
	}()

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		s.log.Printf("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// ---------------------------------------------------------------- helpers

type errorResponse struct {
	Error string `json:"error"`
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{Error: msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
