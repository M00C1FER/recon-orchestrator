// Package tools wraps each ProjectDiscovery binary as a callable tool.
//
// All tools enforce the auth interlock and PII scrubber. Each tool is a thin
// wrapper that builds an argv, runs the binary with a per-tool timeout, and
// returns structured output.
//
// Status:
//   • naabu, ffuf — implemented + smoke-tested
//   • katana, gau, dalfox, arjun, cdncheck, interactsh — interface stubbed
//     with consistent contract; wire the argv when each binary is added.
package tools

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/M00C1FER/recon-orchestrator/internal/auth"
	"github.com/M00C1FER/recon-orchestrator/internal/scrub"
)

// Result is the standard return shape for any tool.
type Result struct {
	Tool       string         `json:"tool"`
	Target     string         `json:"target"`
	OK         bool           `json:"ok"`
	Status     int            `json:"status"`
	Stdout     string         `json:"stdout"`
	Stderr     string         `json:"stderr,omitempty"`
	Duration   string         `json:"duration"`
	ScrubHits  map[string]int `json:"scrub_hits,omitempty"`
	Error      string         `json:"error,omitempty"`
}

// ErrToolMissing is returned when the binary is not on PATH.
var ErrToolMissing = errors.New("tool binary not on PATH")

// Run executes a tool with timeout + scrub. The scope.Authorized check
// MUST run BEFORE Run; this function trusts the caller.
func Run(ctx context.Context, tool string, argv []string, target string, timeout time.Duration) Result {
	start := time.Now()
	if _, err := exec.LookPath(tool); err != nil {
		return Result{Tool: tool, Target: target, OK: false, Error: ErrToolMissing.Error()}
	}
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(c, tool, argv...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	dur := time.Since(start).String()

	scrubbed := scrub.Apply(stdout.String())
	res := Result{
		Tool:      tool,
		Target:    target,
		OK:        err == nil,
		Stdout:    scrubbed.Output,
		Stderr:    stderr.String(),
		Duration:  dur,
		ScrubHits: scrubbed.Hits,
	}
	if cmd.ProcessState != nil {
		res.Status = cmd.ProcessState.ExitCode()
	}
	if err != nil {
		res.Error = err.Error()
	}
	return res
}

// Naabu runs ProjectDiscovery's port scanner against `target`.
// Default ports: top 100. Output: structured JSON lines.
func Naabu(ctx context.Context, scope *auth.Scope, target string, ports string, timeout time.Duration) Result {
	if err := scope.Authorized(target); err != nil {
		return Result{Tool: "naabu", Target: target, OK: false, Error: err.Error()}
	}
	if ports == "" {
		ports = "top-100"
	}
	maxRPS := scope.MaxRPS
	if maxRPS == 0 {
		maxRPS = 100
	}
	argv := []string{"-host", target, "-p", ports, "-rate", fmt.Sprintf("%d", maxRPS), "-silent", "-json"}
	return Run(ctx, "naabu", argv, target, timeout)
}

// Ffuf runs directory/content discovery against `targetURL`.
func Ffuf(ctx context.Context, scope *auth.Scope, targetURL, wordlist string, timeout time.Duration) Result {
	if err := scope.Authorized(targetURL); err != nil {
		return Result{Tool: "ffuf", Target: targetURL, OK: false, Error: err.Error()}
	}
	if wordlist == "" {
		wordlist = defaultWordlist()
	}
	if !strings.Contains(targetURL, "FUZZ") {
		targetURL = strings.TrimRight(targetURL, "/") + "/FUZZ"
	}
	argv := []string{"-u", targetURL, "-w", wordlist, "-of", "json", "-o", "/dev/stdout", "-s"}
	return Run(ctx, "ffuf", argv, targetURL, timeout)
}

// Stub returns a "not yet implemented" structured result for placeholder tools.
// Use this when wiring up the consistent interface; replace with real argv as
// each tool is added.
func Stub(name, target string) Result {
	return Result{
		Tool:   name,
		Target: target,
		OK:     false,
		Error:  fmt.Sprintf("%s wrapper is stubbed in v0.1; PRs welcome", name),
	}
}

// defaultWordlist picks a sensible default per-platform. Operators can always
// override via the `wordlist` request field. Linux/WSL: dirb's common list.
// macOS (Homebrew): seclists. Windows native: explicit override required.
func defaultWordlist() string {
	candidates := []string{
		"/usr/share/wordlists/dirb/common.txt",                                  // Linux / WSL
		"/usr/share/seclists/Discovery/Web-Content/common.txt",                  // Kali / seclists
		"/opt/homebrew/share/seclists/Discovery/Web-Content/common.txt",         // macOS arm64
		"/usr/local/share/seclists/Discovery/Web-Content/common.txt",            // macOS x86_64
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "" // ffuf will error with a clear message; operator must supply
}
