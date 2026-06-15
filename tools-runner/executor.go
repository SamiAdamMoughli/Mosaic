package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"sync"
	"time"
)

// RunRequest is sent by the Python agent layer over HTTP.
type RunRequest struct {
	// Tool name — used only for concurrency limiting and logging.
	Tool string `json:"tool"`
	// Full argv: ["nmap", "-sV", "-p", "80,443", "10.0.0.1"].
	// Python builds this; Go execs it verbatim.
	Argv []string `json:"argv"`
	// Target is the host/IP/URL being acted on, used for scope enforcement.
	// Empty string skips the scope check (for query-style tools like shodan).
	Target string `json:"target"`
	// Timeout in seconds; 0 means use the tool default.
	Timeout int `json:"timeout"`
}

// RunResponse is returned to Python.
type RunResponse struct {
	Output         string `json:"output"`
	Error          string `json:"error"`
	ScopeViolation bool   `json:"scope_violation"`
}

// Per-tool concurrency caps. Mirrors what was previously in Python's registry.
// Goroutine channels are more efficient than asyncio semaphores for subprocess
// fan-out, and context cancellation propagates into every child process.
var toolConcurrency = map[string]int{
	"amass":     1, // memory-hungry; serialise
	"masscan":   2,
	"nmap":      3,
	"rustscan":  3,
	"nuclei":    2,
	"ffuf":      3,
	"katana":    5,
	"gowitness": 3,
}

const defaultConcurrency = 5

// Executor runs tool subprocesses with per-tool concurrency limits.
// It holds no state beyond the semaphore map — safe for concurrent use.
type Executor struct {
	mu   sync.Mutex
	sems map[string]chan struct{}
}

func NewExecutor() *Executor {
	return &Executor{sems: make(map[string]chan struct{})}
}

func (e *Executor) sem(tool string) chan struct{} {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.sems[tool]; !ok {
		limit := defaultConcurrency
		if l, ok := toolConcurrency[tool]; ok {
			limit = l
		}
		e.sems[tool] = make(chan struct{}, limit)
	}
	return e.sems[tool]
}

// Run executes the tool described by req, respecting the concurrency limit and
// the deadline carried by ctx (which is the HTTP request context — so when
// Python cancels the campaign and closes the connection, the subprocess dies).
func (e *Executor) Run(ctx context.Context, req RunRequest) RunResponse {
	if len(req.Argv) == 0 {
		return RunResponse{Error: "empty argv"}
	}

	sem := e.sem(req.Tool)

	// Block until a concurrency slot is free or the context is cancelled.
	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	case <-ctx.Done():
		return RunResponse{Error: "request cancelled while waiting for concurrency slot"}
	}

	timeout := time.Duration(req.Timeout) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Minute
	}

	// Context-scoped timeout: when the campaign is killed (SIGINT/SIGTERM →
	// HTTP server shuts down → request context is cancelled), exec.CommandContext
	// sends SIGKILL to the child process group, so nmap/nuclei/etc. die immediately.
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, req.Argv[0], req.Argv[1:]...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	out := stdout.String()
	errStr := stderr.String()

	if err != nil {
		switch cmdCtx.Err() {
		case context.DeadlineExceeded:
			return RunResponse{
				Output: out, // return whatever partial output we got
				Error:  fmt.Sprintf("timeout after %s", timeout),
			}
		case context.Canceled:
			return RunResponse{Error: "cancelled"}
		}
		// Many security tools exit non-zero but still write useful output.
		if out != "" {
			return RunResponse{Output: out}
		}
		if errStr != "" {
			return RunResponse{Error: errStr}
		}
		return RunResponse{Error: err.Error()}
	}

	return RunResponse{Output: out}
}
