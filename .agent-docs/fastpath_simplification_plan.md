# Implementation Plan: Fast-Path Filter Simplification & Heuristic Decoupling

## Overview

This implementation plan outlines the simplification of the static evaluation pipeline in `jev-guard`. The goal is to eliminate brittle command-line regular expressions and heuristic blacklists/whitelists, while maintaining zero-latency read caching, objective filesystem boundary enforcement, and user credential privacy.

---

## Architecture: Before vs. After

### Current State (Heuristic & Regex-Heavy)
```
Tool Call ──► Fastpath Filter
               ├── Catastrophic Regexes (rm -rf, format, fork bombs)  ──► [DENY]
               ├── Sensitive Substring Matcher (.env, id_rsa)         ──► [ASK]
               ├── Boundary Resolver (target escaping root)           ──► [ASK]
               └── Safe Command & Tool Whitelist (ls, git status...)  ──► [ALLOW]
                     │
                     ▼ (nil / unhandled)
              Main Gate
               ├── Boundary Resolver (redundant second check)
               ├── TypeSafe AI System One (Jev Evaluation)
               └── Policy Evaluator (Thresholds)
```

### Proposed Simplified State (Invariants + Semantic Jev Delegation)
```
Tool Call ──► Invariant & Latency Gate
               ├── 1. Boundary Escape Check (pure path canonicalization)  ──► [ASK]
               ├── 2. Sensitive Credential Pattern (.env, id_rsa, keys)   ──► [ASK]
               ├── 3. Latency Cache: Exact Trusted Read Prefixes          ──► [ALLOW]
               │      (git status, git diff, ls, dir - configurable)
               │
               ▼ (all mutations, complex commands, ambiguous scripts)
              TypeSafe AI System One (Jev)
               ├── is_workspace_contained (Noul)
               ├── destructive_potential (Score 0-3)
               └── violation_category (Choice)
                     │
                     ▼
              Policy Evaluator ──► [ALLOW / ASK / DENY]
```

---

## Key Design Principles

1. **No Brittle Shell Regexes**:
   Shell syntax is unbounded (`rm -rf /`, `rm -r -f /`, `python -c "..."`, base64 encoding). Trying to catch catastrophic commands with regular expressions is inherently brittle. Catastrophic detection belongs to Jev's semantic assessment (`destructive_potential > 2.5` and `violation_category == "catastrophic_deletion"`).

2. **Whitelist Re-framed as "Latency Cache"**:
   Rather than treating the whitelist as a security boundary, it is treated strictly as a performance optimization. Only unambiguous read-only commands without chaining/pipes are fast-tracked to avoid wasting API quota and latency. Everything else flows to Jev.

3. **Invariants Preserved Locally**:
   - **Workspace Boundary**: Mathematical path containment via `filepath.Clean` and canonical symlink resolution.
   - **Sensitive Files**: Protecting `.env`, `.ssh/`, `.aws/` before network transmission to prevent leaking secret metadata.

4. **Deduplication**:
   Remove the duplicate boundary evaluation between `fastpath.Filter` and `main.go`.

5. **Configurability**:
   Wire `.jevguard.json` directly into the gate:
   - `trusted_commands`: Add project-specific read commands that skip Jev.
   - `sensitive_files`: Add project-specific secrets.
   - `fastpath_enabled`: Optional boolean flag to bypass all local gates and force 100% semantic Jev evaluation.

---

## User Review Required

> [!IMPORTANT]
> **Shift from Deterministic Regex to Semantic Jev for Catastrophic Commands**:
> Currently, `rm -rf /`, `format C:`, and fork bombs are intercepted by regex patterns in `pkg/fastpath/filter.go` and return `DENY` locally.
> Under this plan, these regexes are removed because shell syntax is unbounded and regexes are easily bypassed (`rm -r -f /`, base64 encoding, python scripts). Instead, these commands are evaluated by TypeSafe AI System One (`destructive_potential: 3.0` and `violation_category: "catastrophic_deletion"`), which triggers `DENY` via `pkg/policy/evaluator.go`.
> 
> *Fallback guarantee*: If TypeSafe AI is unavailable or times out, the fail-safe policy resolves to `ASK` (prompting the user), preventing unconfirmed execution.

> [!NOTE]
> **Preserving Zero-Latency Read Operations**:
> Rather than a fuzzy whitelist, we preserve a fast-path "Latency Cache" for unambiguous inspection commands (`git status`, `git diff`, `ls`, `dir`, `pwd`) and safe read tools. This prevents burning API tokens and incurring 100–500ms network roundtrips on everyday agent inspections.

---

## Open Questions

> [!IMPORTANT]
> **Bypass Toggle**: Would you prefer an explicit `"fastpath_enabled": false` setting in `.jevguard.json` that allows completely disabling all local checks (forcing 100% of calls to Jev), or should the fastpath always run for trusted command latency caching?

---

## Proposed Changes

Grouped by component layer:

### Fast-Path Filter Layer

#### [MODIFY] [pkg/fastpath/filter.go](file:///c:/dev/jev-typesafeai/pkg/fastpath/filter.go)
- **Remove**:
  - `catastrophicRegexes []*regexp.Regexp` and `compileCatastrophicPatterns()`.
  - `safeTools map[string]bool` hardcoded dictionary.
- **Refactor**:
  - Update `Filter` struct to hold a reference to `*config.Config` and `BoundaryChecker`.
  - Provide focused helper methods under 25 lines:
    - `checkSensitivePaths(call *harness.NormalizedToolCall) string`: Checks target path and arguments against configured/default sensitive patterns (`.env*`, `id_rsa`, `.pem`).
    - `checkBoundary(call *harness.NormalizedToolCall) string`: Uses `BoundaryChecker` to verify target path containment.
    - `isTrustedCommand(call *harness.NormalizedToolCall) bool`: Checks if `call.Command` starts with any entry in `cfg.TrustedCommands` (and does not contain chaining operators `;`, `&&`, `|`, etc.).
  - `Evaluate(call)` delegates cleanly to these sub-routines.

#### [MODIFY] [pkg/fastpath/filter_test.go](file:///c:/dev/jev-typesafeai/pkg/fastpath/filter_test.go)
- Update test cases:
  - Remove expectations of fastpath regex `DENY` on `rm -rf /` (mutating commands now return `nil` to pass through to Jev).
  - Add test asserting that `rm -rf /` passes through fastpath as `nil`.
  - Verify sensitive files (`.env`) still produce `ASK`.
  - Verify trusted commands (`git status`, `ls`) produce `ALLOW`.
  - Verify chained commands (`git status; rm -rf /`) pass through to Jev (`nil`).

---

### Configuration & Orchestration Layer

#### [MODIFY] [pkg/config/config.go](file:///c:/dev/jev-typesafeai/pkg/config/config.go)
- Add `FastpathEnabled bool` (default: `true`) to `Config`.
- Set standard defaults for `TrustedCommands` (`git status`, `git diff`, `git log`, `git branch`, `ls`, `dir`, `pwd`) and `SensitiveFiles` (`.env`, `id_rsa`, `id_ed25519`, `.ssh/`, `.aws/`, `credentials.json`, `.pem`, `.key`).
- Allow `.jevguard.json` to customize or extend these lists.

#### [MODIFY] [main.go](file:///c:/dev/jev-typesafeai/main.go)
- In `executeGateEvaluation`:
  - Pass `cfg` into `fastpath.NewFilter(...)`.
  - If `!cfg.FastpathEnabled`, bypass fastpath evaluation entirely.
  - Consolidate boundary checking: use the result from fastpath or perform it once during semantic policy resolution, removing the redundant duplicate resolution.

---

### Documentation Layer

#### [MODIFY] [README.md](file:///c:/dev/jev-typesafeai/README.md)
- Clarify the separation of concerns:
  - Fastpath = Latency cache for known inspection commands + local credential/boundary guards.
  - TypeSafe AI (Jev) = Destructive potential, blast radius assessment, and catastrophic threat detection.

---

## Verification Plan

### Automated Tests
```powershell
go test -v ./...
```
- Verify all unit tests across `pkg/fastpath`, `pkg/boundary`, `pkg/config`, `pkg/evaluator`, `pkg/policy`, and `pkg/harness` pass.
- Verify sub-millisecond execution time on `pkg/fastpath`.

### Manual Verification
- Compile binary:
  ```powershell
  go build -o jev-guard.exe main.go
  ```
- Test trusted command (latency cache):
  - Pipe `{"tool_name": "Bash", "tool_input": {"command": "git status"}, "cwd": "."}` -> Confirm instant `ALLOW`.
- Test destructive command delegation:
  - Pipe `{"tool_name": "Bash", "tool_input": {"command": "rm -rf /tmp/foo"}, "cwd": "."}` -> Confirm it bypasses fastpath and invokes TypeSafe evaluation.

---

## Implementation Status & Verification Record

- **Status**: Completed (2026-09-18)
- **Changes Applied**:
  - **`pkg/fastpath/filter.go`**: Removed regex pattern compilation (`catastrophicRegexes`, `compileCatastrophicPatterns`) and broad `safeTools` map. Refactored into focused single-responsibility routines (`checkSensitive`, `checkBoundaryEscape`, `isTrustedCommand`).
  - **`pkg/fastpath/filter_test.go`**: Added test verifying catastrophic commands pass through to Jev (`nil`). Verified sensitive files, boundary escapes, trusted commands, and config injection.
  - **`pkg/config/config.go` & `pkg/config/config_test.go`**: Added `FastpathEnabled *bool` with `IsFastpathEnabled()` helper, `DefaultSensitiveFiles()`, `DefaultTrustedCommands()`, environment variable `JEV_GUARD_FASTPATH_ENABLED`, and unique string merging. Added 3 new unit tests.
  - **`main.go`**: Injected `cfg` into `fastpath.NewFilter(checker, cfg)` and gated execution on `cfg.IsFastpathEnabled()`.
  - **`README.md`**: Updated key features and configuration precedence documentation.
- **Verification Results**:
  - `go test -count=1 ./...` passed across all packages (`pkg/boundary`, `pkg/cli`, `pkg/config`, `pkg/evaluator`, `pkg/fastpath`, `pkg/harness`, `pkg/policy`).
