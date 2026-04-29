// Package scrub redacts secrets/PII from tool output before it ships in a report.
package scrub

import (
	"regexp"
	"strings"
)

var patterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"AWS_ACCESS_KEY", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"AWS_SECRET", regexp.MustCompile(`(?i)aws.{0,20}?(?:secret|key).{0,5}[\s:=]{1,3}["']?[A-Za-z0-9/+=]{40}["']?`)},
	{"GH_TOKEN", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,}`)},
	{"GH_FINEGRAINED", regexp.MustCompile(`github_pat_[A-Za-z0-9_]{82}`)},
	{"SLACK", regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`)},
	{"JWT", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
	{"PRIVATE_KEY", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----`)},
	{"EMAIL", regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)},
	{"BEARER", regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9._-]{20,}`)},
}

// Result of a scrub call.
type Result struct {
	Output string         `json:"output"`
	Hits   map[string]int `json:"hits"`
}

// Apply walks the patterns and redacts each match with [REDACTED:NAME].
func Apply(s string) Result {
	hits := make(map[string]int)
	out := s
	for _, p := range patterns {
		out = p.re.ReplaceAllStringFunc(out, func(m string) string {
			hits[p.name]++
			return "[REDACTED:" + p.name + "]"
		})
	}
	return Result{Output: out, Hits: hits}
}

// SafeForReport returns true when no scrub hits occurred (call after Apply).
func SafeForReport(r Result) bool {
	for _, n := range r.Hits {
		if n > 0 {
			return false
		}
	}
	return true
}

// Inert is a sentinel used by tests to ensure a string isn't accidentally redacted.
func Inert(s string) bool {
	return !strings.Contains(Apply(s).Output, "[REDACTED:")
}
