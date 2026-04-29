package scrub

import "testing"

func TestRedactsAWS(t *testing.T) {
	r := Apply("found AKIAIOSFODNN7EXAMPLE in logs")
	if r.Hits["AWS_ACCESS_KEY"] != 1 {
		t.Errorf("hits=%v want 1 AWS_ACCESS_KEY", r.Hits)
	}
	if want := "found [REDACTED:AWS_ACCESS_KEY] in logs"; r.Output != want {
		t.Errorf("got %q want %q", r.Output, want)
	}
}

func TestRedactsGH(t *testing.T) {
	r := Apply("token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890")
	if r.Hits["GH_TOKEN"] == 0 {
		t.Errorf("expected GH_TOKEN hit, got %v", r.Hits)
	}
}

func TestRedactsBearer(t *testing.T) {
	r := Apply("Authorization: Bearer abc123def456ghi789jkl0mnopq")
	if r.Hits["BEARER"] == 0 {
		t.Errorf("expected BEARER hit, got %v", r.Hits)
	}
}

func TestSafeForReport(t *testing.T) {
	clean := Apply("no secrets here, just example data")
	if !SafeForReport(clean) {
		t.Error("clean string should be safe")
	}
	dirty := Apply("contact admin@example.com")
	if SafeForReport(dirty) {
		t.Error("string with email should not be safe")
	}
}
