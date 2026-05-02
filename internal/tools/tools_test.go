package tools

import (
	"context"
	"testing"
	"time"

	"github.com/M00C1FER/recon-orchestrator/internal/auth"
)

// validScope returns a minimal authorized scope for test use.
func validScope(targets ...string) *auth.Scope {
	if len(targets) == 0 {
		targets = []string{"example.com"}
	}
	return &auth.Scope{
		Targets:         targets,
		ROEAccepted:     true,
		ROEAcceptedBy:   "tester@example.com",
		ROEAcceptedDate: "2026-05-02",
		MaxRPS:          5,
	}
}

func TestStub_ReturnsNotImplemented(t *testing.T) {
	for _, name := range []string{"katana", "gau", "dalfox", "arjun", "cdncheck", "interactsh"} {
		r := Stub(name, "example.com")
		if r.OK {
			t.Errorf("Stub(%q): expected OK=false", name)
		}
		if r.Error == "" {
			t.Errorf("Stub(%q): expected non-empty Error", name)
		}
		if r.Tool != name {
			t.Errorf("Stub(%q): Tool=%q want %q", name, r.Tool, name)
		}
	}
}

func TestNaabu_RejectsOutOfScope(t *testing.T) {
	s := validScope("example.com")
	r := Naabu(context.Background(), s, "evil.com", "", 5*time.Second)
	if r.OK {
		t.Error("Naabu: expected OK=false for out-of-scope target")
	}
	if r.Error == "" {
		t.Error("Naabu: expected non-empty Error for out-of-scope target")
	}
}

func TestNaabu_RejectsPrivateIP(t *testing.T) {
	s := validScope("example.com")
	r := Naabu(context.Background(), s, "127.0.0.1", "", 5*time.Second)
	if r.OK {
		t.Error("Naabu: expected OK=false for loopback target")
	}
	if r.Error == "" {
		t.Error("Naabu: expected non-empty Error for loopback target")
	}
}

func TestFfuf_RejectsOutOfScope(t *testing.T) {
	s := validScope("example.com")
	r := Ffuf(context.Background(), s, "https://evil.com/", "", 5*time.Second)
	if r.OK {
		t.Error("Ffuf: expected OK=false for out-of-scope target")
	}
	if r.Error == "" {
		t.Error("Ffuf: expected non-empty Error for out-of-scope target")
	}
}

func TestFfuf_RejectsPrivateIP(t *testing.T) {
	s := validScope("example.com")
	r := Ffuf(context.Background(), s, "http://192.168.1.1/", "", 5*time.Second)
	if r.OK {
		t.Error("Ffuf: expected OK=false for private IP target")
	}
}

func TestRun_BinaryMissing(t *testing.T) {
	r := Run(context.Background(), "no-such-binary-xyz", []string{}, "example.com", 5*time.Second)
	if r.OK {
		t.Error("Run: expected OK=false when binary is missing")
	}
	if r.Error != ErrToolMissing.Error() {
		t.Errorf("Run: Error=%q want %q", r.Error, ErrToolMissing.Error())
	}
}
