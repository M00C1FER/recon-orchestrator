// Package auth implements the scope.yaml authorization interlock.
// Every recon run MUST present a valid scope file declaring authorized targets
// and ROE acknowledgment. Without it, all tool calls are refused.
package auth

import (
	"errors"
	"fmt"
	"net"
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
	ErrPrivateTarget   = errors.New("target resolves to a private/loopback address (SSRF guard)")
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
	if !s.ROEAccepted || strings.TrimSpace(s.ROEAcceptedBy) == "" || strings.TrimSpace(s.ROEAcceptedDate) == "" {
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
	// SSRF guard: reject private/loopback addresses before checking scope.
	if isPrivateHost(host) {
		return fmt.Errorf("%w: %q", ErrPrivateTarget, target)
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
	// Strip path/port if present.
	t := strings.ToLower(target)
	// A bare IPv6 address (e.g. "::1", "fc00::1") contains colons but no
	// scheme. Detect it before the generic colon-strip below.
	if ip := net.ParseIP(t); ip != nil && ip.To4() == nil {
		// It's an IPv6 address — return as-is (already lower-cased).
		return t
	}
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

// isPrivateHost returns true when host is a loopback address, an RFC-1918
// private address, or an IPv6 link-local/loopback address. This is a
// defence-in-depth SSRF guard: even if an operator accidentally adds a
// private address to scope.yaml we won't scan it.
func isPrivateHost(host string) bool {
	// Explicit name checks first.
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return true
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false // non-IP hostname — not blocked here
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	// RFC-1918 and other special-use ranges.
	private := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",  // RFC-6598 shared address (carrier-grade NAT)
		"169.254.0.0/16", // link-local / cloud metadata (AWS 169.254.169.254)
		"fc00::/7",       // IPv6 unique-local
	}
	for _, cidr := range private {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
