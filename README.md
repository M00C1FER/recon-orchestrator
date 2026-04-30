> ⚠️ **DEPRECATED — v0.1 archived 2026-04-30.**  This repo was a portfolio exercise. After a 12-iteration / 27-domain competitive analysis, the recommended production path is:
>
> **h1-brain** (https://github.com/PatrikFehrenbach/h1-brain) — 3,600+ pre-built bounty reports · **pentest-agents** (https://github.com/H-mmer/pentest-agents) — 48 agents, 26 commands, comprehensive framework
>
> The code below remains available for reference but is **no longer maintained**. See the linked alternatives for production use.

# recon-orchestrator

> Authorization-gated MCP server for ethical bug-bounty / pentest recon. Native Go (single 9.6 MB binary). Refuses to run without `scope.yaml` + ROE acceptance. PII-scrubs all output. For HackerOne / Bugcrowd researchers.

[![CI](https://github.com/M00C1FER/recon-orchestrator/actions/workflows/ci.yml/badge.svg)](https://github.com/M00C1FER/recon-orchestrator/actions)

## Why native Go

Every wrapped tool — `naabu`, `katana`, `gau`, `dalfox`, `ffuf`, `arjun`, `cdncheck`, `interactsh` — is **already Go**. Calling them from Python via subprocess is the worst of both worlds. This MCP server is Go-native: lower cold-start, single static binary, no Python runtime needed on the operator box.

## What it does

- **Authorization interlock** — every call is gated on `scope.yaml` + ROE acceptance. Out-of-scope targets are **refused** before any binary executes.
- **PII scrubber** — output is run through a 9-pattern redactor (AWS keys, GH tokens, JWTs, Bearer tokens, private keys, emails, etc.) before it leaves the process.
- **Browser-discipline aware** — `browser_allowed: false` in scope.yaml gates all Tier-3 (headless rendering) tools. Default off.
- **Per-tool timeout + rate caps** — `max_rps` from scope flows to every wrapped tool.
- **Structured output** — every tool returns `{tool, target, ok, stdout, stderr, duration, scrub_hits, error}`.

## Status (v0.1)

| Tool | Status | Notes |
|---|---|---|
| `naabu` | ✅ implemented | Top-100 ports, JSON output, rate-capped |
| `ffuf` | ✅ implemented | Auto-injects `FUZZ` if absent |
| `katana` | 🟡 stubbed | Interface ready; argv pending |
| `gau` | 🟡 stubbed | Interface ready; argv pending |
| `dalfox` | 🟡 stubbed | Interface ready; argv pending |
| `arjun` | 🟡 stubbed | Interface ready; argv pending |
| `cdncheck` | 🟡 stubbed | Interface ready; argv pending |
| `interactsh` | 🟡 stubbed | Interface ready; argv pending |

The stubs return a consistent error structure so MCP clients can degrade gracefully while wrappers are added. Each new wrapper is ~30 LOC + a test.

## Quick start

```bash
go install github.com/M00C1FER/recon-orchestrator/cmd/recon-orchestrator@latest
cp $(go env GOPATH)/src/github.com/M00C1FER/recon-orchestrator/examples/scope.example.yaml ./scope.yaml
# Edit scope.yaml — set targets + ROE acceptance.
recon-orchestrator -scope ./scope.yaml -addr 127.0.0.1:8092
```

```bash
# Out-of-scope target → refused
$ curl -X POST http://127.0.0.1:8092/tool/naabu -d '{"target":"evil.com"}'
{"tool":"naabu","target":"evil.com","ok":false,"error":"target not in authorized scope"}

# In-scope target → runs
$ curl -X POST http://127.0.0.1:8092/tool/naabu -d '{"target":"example.com","ports":"80,443"}'
{"tool":"naabu","target":"example.com","ok":true,"stdout":"..."}
```

## scope.yaml contract

```yaml
engagement: "HackerOne — example-corp"
targets:
  - example.com
  - "*.example.com"
out_of_scope:
  - admin.example.com   # explicit deny wins over targets
roe_accepted: true
roe_accepted_by: your-handle@example.com
roe_accepted_date: 2026-04-29
bounty: hackerone
max_rps: 5
browser_allowed: false  # gates Tier-3 tools
```

## Comparison

| | Auth interlock | ROE template | Browser gate | PII scrubber | Native Go |
|---|:-:|:-:|:-:|:-:|:-:|
| Random ProjectDiscovery wrappers | ❌ | ❌ | ❌ | ❌ | varies |
| `bishopfox/sliver-mcp` (proprietary) | partial | ❌ | ❌ | ❌ | ❌ |
| **`recon-orchestrator`** | **✅** | **✅** | **✅** | **✅** | **✅** |

## Testing

```bash
go test ./...
```

Auth tests validate scope parsing, ROE enforcement, wildcard targets, out-of-scope deny. Scrub tests cover AWS keys, GH tokens, Bearer tokens.

## License

MIT.
