// Package auth implements the scope.yaml authorization interlock.
// Every recon run MUST present a valid scope file declaring authorized targets
// and ROE acknowledgment. Without it, all tool calls are refused.
package auth

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Scope is the parsed scope.yaml structure.
type Scope struct {
	Engagement      string   `yaml:"engagement"`
	Targets         []string `yaml:"targets"`         // domain or CIDR
	OutOfScope      []string `yaml:"out_of_scope"`    // exclusions
	ROEAccepted     bool     `yaml:"roe_accepted"`    // must be true
	ROEAcceptedBy   string   `yaml:"roe_accepted_by"` // email/handle
	ROEAcceptedDate string   `yaml:"roe_accepted_date"`
	Bounty          string   `yaml:"bounty,omitempty"`     // hackerone/bugcrowd/private
	MaxRPS          int      `yaml:"max_rps,omitempty"`    // tool rate cap
	BrowserAllowed  bool     `yaml:"browser_allowed"`      // gates Tier-3 tools
}

var (
	ErrMissingScope    = errors.New("scope.yaml required (set RECON_SCOPE=path/to/scope.yaml)")
	ErrROENotAccepted  = errors.New("scope.yaml must set roe_accepted: true with roe_accepted_by + roe_accepted_date")
	ErrNoTargets       = errors.New("scope.yaml must declare at least one target domain or CIDR")
	ErrTargetForbidden = errors.New("target not in authorized scope")
)

// Load reads and validates scope.yaml.
func Load(path string) (*Scope, error) {
	if path == "" {
		path = os.Getenv("RECON_SCOPE")
	}
	if path == "" {
		return nil, ErrMissingScope
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read scope: %w", err)
	}
	var s Scope
	if err := yaml.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("parse scope.yaml: %w", err)
	}
	if !s.ROEAccepted || s.ROEAcceptedBy == "" || s.ROEAcceptedDate == "" {
		return nil, ErrROENotAccepted
	}
	if len(s.Targets) == 0 {
		return nil, ErrNoTargets
	}
	return &s, nil
}

// Authorized returns nil if the target is permitted, an error otherwise.
func (s *Scope) Authorized(target string) error {
	host := normalizeHost(target)
	if host == "" {
		return fmt.Errorf("%w: %q (cannot parse host)", ErrTargetForbidden, target)
	}
	// Out-of-scope wins
	for _, oos := range s.OutOfScope {
		if matches(host, oos) {
			return fmt.Errorf("%w: %q matches out_of_scope %q", ErrTargetForbidden, target, oos)
		}
	}
	for _, t := range s.Targets {
		if matches(host, t) {
			return nil
		}
	}
	return fmt.Errorf("%w: %q not in targets list", ErrTargetForbidden, target)
}

func normalizeHost(target string) string {
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err != nil {
			return ""
		}
		return strings.ToLower(u.Hostname())
	}
	// Strip path/port if present
	t := strings.ToLower(target)
	if i := strings.IndexAny(t, ":/"); i >= 0 {
		t = t[:i]
	}
	return t
}

// matches handles "*.example.com" wildcard suffix and exact host.
func matches(host, pattern string) bool {
	pattern = strings.ToLower(pattern)
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		return host == suffix || strings.HasSuffix(host, "."+suffix)
	}
	return host == pattern
}
