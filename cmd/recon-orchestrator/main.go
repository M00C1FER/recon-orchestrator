// recon-orchestrator is an MCP-style HTTP server exposing authorized recon tools.
//
// The server binds an MCP-compatible JSON tool surface over HTTP. Each tool
// requires a valid scope.yaml to be loaded; all calls are authorization-gated
// + PII-scrubbed + structured.
//
// Usage:
//   recon-orchestrator -scope ./scope.yaml -addr 127.0.0.1:8092
//
// Endpoints (each is `POST /tool/<name>` with JSON body):
//   /tool/naabu          {"target":"x.com","ports":"top-100"}
//   /tool/ffuf           {"target":"https://x.com/FUZZ","wordlist":"..."}
//   /tool/katana         (stub)
//   /tool/gau            (stub)
//   /tool/dalfox         (stub)
//   /tool/arjun          (stub)
//   /tool/cdncheck       (stub)
//   /tool/interactsh     (stub)
//
//   GET /healthz                 — daemon liveness
//   GET /scope                   — currently-loaded scope (sanitized)
//   GET /tools                   — list available tools
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/M00C1FER/recon-orchestrator/internal/auth"
	"github.com/M00C1FER/recon-orchestrator/internal/tools"
)

type server struct {
	scope *auth.Scope
}

type toolReq struct {
	Target   string `json:"target"`
	Ports    string `json:"ports"`
	Wordlist string `json:"wordlist"`
	Timeout  int    `json:"timeout_s"`
}

func (s *server) writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *server) bindReq(w http.ResponseWriter, r *http.Request) (*toolReq, bool) {
	var req toolReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return nil, false
	}
	if req.Timeout == 0 {
		req.Timeout = 60
	}
	return &req, true
}

func (s *server) registerTools(mux *http.ServeMux) {
	mux.HandleFunc("/tool/naabu", func(w http.ResponseWriter, r *http.Request) {
		req, ok := s.bindReq(w, r)
		if !ok {
			return
		}
		res := tools.Naabu(r.Context(), s.scope, req.Target, req.Ports, time.Duration(req.Timeout)*time.Second)
		s.writeJSON(w, 200, res)
	})
	mux.HandleFunc("/tool/ffuf", func(w http.ResponseWriter, r *http.Request) {
		req, ok := s.bindReq(w, r)
		if !ok {
			return
		}
		res := tools.Ffuf(r.Context(), s.scope, req.Target, req.Wordlist, time.Duration(req.Timeout)*time.Second)
		s.writeJSON(w, 200, res)
	})
	for _, name := range []string{"katana", "gau", "dalfox", "arjun", "cdncheck", "interactsh"} {
		n := name
		mux.HandleFunc("/tool/"+n, func(w http.ResponseWriter, r *http.Request) {
			req, ok := s.bindReq(w, r)
			if !ok {
				return
			}
			s.writeJSON(w, 200, tools.Stub(n, req.Target))
		})
	}
}

func main() {
	scopePath := flag.String("scope", "", "path to scope.yaml (required)")
	addr := flag.String("addr", "127.0.0.1:8092", "listen address")
	flag.Parse()

	scope, err := auth.Load(*scopePath)
	if err != nil {
		log.Fatalf("scope load: %v", err)
	}
	log.Printf("recon-orchestrator: scope %q loaded (%d targets, ROE accepted)",
		scope.Engagement, len(scope.Targets))

	srv := &server{scope: scope}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		srv.writeJSON(w, 200, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/scope", func(w http.ResponseWriter, _ *http.Request) {
		// Sanitized scope: omit ROE acceptor for privacy.
		srv.writeJSON(w, 200, map[string]any{
			"engagement":      scope.Engagement,
			"targets":         scope.Targets,
			"out_of_scope":    scope.OutOfScope,
			"max_rps":         scope.MaxRPS,
			"browser_allowed": scope.BrowserAllowed,
		})
	})
	mux.HandleFunc("/tools", func(w http.ResponseWriter, _ *http.Request) {
		srv.writeJSON(w, 200, map[string]any{
			"implemented": []string{"naabu", "ffuf"},
			"stubbed":     []string{"katana", "gau", "dalfox", "arjun", "cdncheck", "interactsh"},
		})
	})
	srv.registerTools(mux)

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		log.Printf("recon-orchestrator listening on %s", *addr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	<-ctx.Done()
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
	log.Println("recon-orchestrator: shutdown complete")
}
