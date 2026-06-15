// recon-runner — Go tool execution sidecar for the Python recon agent system.
//
// Why Go instead of Python asyncio subprocess:
//   - exec.CommandContext propagates cancellation into the child process tree;
//     when the campaign is killed, every running nmap/nuclei/ffuf dies instantly.
//   - Goroutine channel semaphores are more efficient than asyncio.Semaphore for
//     high fan-out subprocess scenarios.
//   - Single compiled binary: no Python version, virtualenv, or pip dependencies
//     needed on the target machine alongside the security tools.
//
// Python keeps: LLM orchestration, tool argv construction, scope definition.
// Go keeps: subprocess execution, concurrency limiting, scope enforcement,
//           graceful shutdown signal propagation.
//
// Usage:
//
//	recon-runner --port 7373 --scope '{"networks":["10.0.0.0/24"],"domains":["example.com"]}'
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var (
	portFlag  = flag.Int("port", 7373, "Port to listen on (loopback only)")
	scopeFlag = flag.String("scope", "{}", "Campaign scope as JSON")
)

func main() {
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmsgprefix)
	log.SetPrefix("runner ")

	var scopeCfg struct {
		Networks []string `json:"networks"`
		Domains  []string `json:"domains"`
		Excluded []string `json:"excluded"`
	}
	if err := json.Unmarshal([]byte(*scopeFlag), &scopeCfg); err != nil {
		log.Fatalf("invalid --scope JSON: %v", err)
	}

	scope, err := NewScope(scopeCfg.Networks, scopeCfg.Domains, scopeCfg.Excluded)
	if err != nil {
		log.Fatalf("scope config error: %v", err)
	}

	exec := NewExecutor()

	mux := http.NewServeMux()

	// Health probe — Python polls this after spawning the process.
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`)) //nolint:errcheck
	})

	// Main tool execution endpoint.
	mux.HandleFunc("/run", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}

		var req RunRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("bad request: %v", err), http.StatusBadRequest)
			return
		}

		// Scope enforcement — second layer (Python already checked, but this
		// is the authoritative gate at the execution boundary).
		if req.Target != "" {
			if err := scope.Check(req.Target); err != nil {
				log.Printf("SCOPE VIOLATION: %v", err)
				writeJSON(w, RunResponse{
					ScopeViolation: true,
					Error:          err.Error(),
				})
				return
			}
		}

		log.Printf("[%s] %v", req.Tool, req.Argv)
		resp := exec.Run(r.Context(), req)
		writeJSON(w, resp)
	})

	addr := fmt.Sprintf("127.0.0.1:%d", *portFlag)
	srv := &http.Server{Addr: addr, Handler: mux}

	// Graceful shutdown on SIGINT / SIGTERM.
	// In-flight /run requests complete normally; the subprocess context is
	// tied to the HTTP request context and is cancelled when the connection closes.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		log.Println("shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("shutdown error: %v", err)
		}
	}()

	log.Printf("listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("response encode error: %v", err)
	}
}
