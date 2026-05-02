package auth

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeScope(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "scope.yaml")
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad_ValidScope(t *testing.T) {
	p := writeScope(t, `
engagement: HackerOne — example-corp
targets:
  - example.com
  - "*.example.com"
out_of_scope:
  - admin.example.com
roe_accepted: true
roe_accepted_by: roe-acceptor@example.com
roe_accepted_date: 2026-04-29
bounty: hackerone
max_rps: 5
`)
	s, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if s.Engagement == "" || len(s.Targets) != 2 {
		t.Errorf("scope parsed wrong: %+v", s)
	}
}

func TestLoad_MissingPath(t *testing.T) {
	t.Setenv("RECON_SCOPE", "")
	_, err := Load("")
	if !errors.Is(err, ErrMissingScope) {
		t.Errorf("got %v want ErrMissingScope", err)
	}
}

func TestLoad_ROENotAccepted(t *testing.T) {
	p := writeScope(t, `
targets: [example.com]
roe_accepted: false
`)
	_, err := Load(p)
	if !errors.Is(err, ErrROENotAccepted) {
		t.Errorf("got %v want ErrROENotAccepted", err)
	}
}

// TestLoad_ROEWhitespaceBypassed ensures that a blank/whitespace-only
// roe_accepted_by does not pass validation.
func TestLoad_ROEWhitespaceBypassed(t *testing.T) {
	p := writeScope(t, `
targets: [example.com]
roe_accepted: true
roe_accepted_by: "   "
roe_accepted_date: "   "
`)
	_, err := Load(p)
	if !errors.Is(err, ErrROENotAccepted) {
		t.Errorf("got %v want ErrROENotAccepted (whitespace-only fields)", err)
	}
}

func TestAuthorized_AllowsExact(t *testing.T) {
	s := &Scope{Targets: []string{"example.com"}, ROEAccepted: true}
	if err := s.Authorized("example.com"); err != nil {
		t.Errorf("got %v want nil", err)
	}
}

func TestAuthorized_AllowsWildcard(t *testing.T) {
	s := &Scope{Targets: []string{"*.example.com"}, ROEAccepted: true}
	for _, ok := range []string{"api.example.com", "deep.nested.example.com", "example.com"} {
		if err := s.Authorized(ok); err != nil {
			t.Errorf("got %v want nil for %q", err, ok)
		}
	}
}

func TestAuthorized_RejectsOutOfScope(t *testing.T) {
	s := &Scope{
		Targets:     []string{"*.example.com"},
		OutOfScope:  []string{"admin.example.com"},
		ROEAccepted: true,
	}
	if err := s.Authorized("admin.example.com"); err == nil {
		t.Error("admin.example.com should be denied")
	}
}

func TestAuthorized_RejectsForeign(t *testing.T) {
	s := &Scope{Targets: []string{"example.com"}, ROEAccepted: true}
	if err := s.Authorized("evil.com"); err == nil {
		t.Error("evil.com should be denied")
	}
}

func TestAuthorized_NormalizesURL(t *testing.T) {
	s := &Scope{Targets: []string{"example.com"}, ROEAccepted: true}
	if err := s.Authorized("https://example.com:8443/path"); err != nil {
		t.Errorf("got %v want nil for URL form", err)
	}
}

// TestAuthorized_RejectsPrivateIPs verifies the SSRF guard.
func TestAuthorized_RejectsPrivateIPs(t *testing.T) {
	s := &Scope{Targets: []string{"example.com"}, ROEAccepted: true}
	privateTargets := []string{
		"127.0.0.1",
		"localhost",
		"10.0.0.1",
		"192.168.1.1",
		"172.16.0.5",
		"169.254.169.254", // AWS metadata
		"::1",
	}
	for _, target := range privateTargets {
		err := s.Authorized(target)
		if !errors.Is(err, ErrPrivateTarget) {
			t.Errorf("target %q: got %v, want ErrPrivateTarget", target, err)
		}
	}
}

// TestAuthorized_RejectsLocalhostSubdomains verifies the SSRF guard for
// .localhost subdomains.
func TestAuthorized_RejectsLocalhostSubdomains(t *testing.T) {
	s := &Scope{Targets: []string{"*.localhost"}, ROEAccepted: true}
	if err := s.Authorized("internal.localhost"); !errors.Is(err, ErrPrivateTarget) {
		t.Errorf("internal.localhost should be rejected as private, got %v", err)
	}
}

