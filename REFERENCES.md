# Reference Projects

Projects studied during the 2026-05-02 audit cycle.

## 1. projectdiscovery/nuclei (≥21 k stars, MIT)

**Pattern: Interactivity-gated execution.**  
Nuclei gates destructive/active templates behind explicit `-ept active` or `-dast`
flags and refuses to run out-of-scope hosts when a target list is provided. The
same pattern underpins this repo's `scope.yaml` interlock: a static file
declaring authorized targets that must be present before any binary runs.

<https://github.com/projectdiscovery/nuclei>

## 2. ffuf/ffuf (≥13 k stars, MIT)

**Pattern: Per-run rate cap via CLI flag.**  
ffuf exposes `-rate N` to cap requests per second globally across all goroutines.
This repo's audit found that the ffuf wrapper was not threading `scope.MaxRPS`
through to `-rate`; that gap is fixed in this PR.

<https://github.com/ffuf/ffuf>

## 3. tomnomnom/waybackurls (≥4 k stars, MIT)

**Pattern: Single-purpose, pipe-friendly, no auth surface.**  
waybackurls outputs plain URLs to stdout, making it trivial to compose with
scrubbers in a pipeline. Inspired the structured `{tool, target, ok, stdout,
stderr, duration, scrub_hits}` contract used here so callers can always scrub
before logging.

<https://github.com/tomnomnom/waybackurls>

## 4. gitleaks/gitleaks (≥18 k stars, MIT)

**Pattern: Regex-based secret scanning with named rule IDs.**  
Gitleaks tags every match with a `RuleID` string so consumers can track hit
counts per pattern type. This repo's `scrub.Result.Hits` map (`map[string]int`
keyed by pattern name) mirrors that design, allowing callers to distinguish
`AWS_ACCESS_KEY` hits from `GH_TOKEN` hits rather than a bare boolean.

<https://github.com/gitleaks/gitleaks>

## 5. lc/gau (≥3.7 k stars, MIT)

**Pattern: Rate-limiting via `--subs` + per-provider throttle.**  
gau routes requests across multiple providers and applies per-provider rate
limits to avoid hammering any single source. The rate-limit-per-scope-file
approach used here (`max_rps` flows to every wrapped binary) generalises this
pattern to the whole orchestrator level rather than per-provider.

<https://github.com/lc/gau>
