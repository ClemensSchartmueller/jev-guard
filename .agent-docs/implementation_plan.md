# Implementation Plan: `jev-guard` Universal Tool Safety Gate

`jev-guard` is a high-speed, cross-agent safety plugin for **Claude Code**, **Codex CLI**, and **Antigravity**. It intercepts native pre-tool executions (shell commands, file modifications, patches), applies sub-millisecond local boundary and sensitive file checks, and utilizes **TypeSafe AI's Jev** System One model to evaluate blast radius, reversibility, and destructive potential.

---

## User Review Required

> [!IMPORTANT]
> **No Go Toolchain Required for End Users**: The repository will include a CI release workflow (GoReleaser/GitHub Actions) and 1-line installation scripts (`install.sh` and `install.ps1`) that automatically download pre-compiled, static single binaries for Windows, macOS, and Linux into `~/.local/bin/`.

> [!IMPORTANT]
> **Zero-Latency Fast-Path**: Routine inspection operations (`ls`, `git status`, `view_file`, `cat README.md`) resolve in **< 3ms** without hitting the network. TypeSafe Jev is invoked only for mutating or ambiguous operations.

---

## Architecture & System Design

```
                  ┌────────────────────────────────────────┐
                  │          Tool Invocation               │
                  │   Claude Code / Codex / Antigravity    │
                  └───────────────────┬────────────────────┘
                                      │ (stdin JSON)
                                      ▼
                  ┌────────────────────────────────────────┐
                  │            jev-guard (Go)              │
                  │  1. Detect Harness & Normalize Payload │
                  │  2. Resolve Git Workspace Root         │
                  └───────────────────┬────────────────────┘
                                      │
              ┌───────────────────────┴───────────────────────┐
              │ Local Static Filter (< 2ms)                   │
              ├───────────────────────────────────────────────┤
              │ • Sensitive File Blacklist (.env, keys) ───►  │ ──► [ASK] (Immediate)
              │ • Known Catastrophic Strings (rm -rf /) ───►  │ ──► [DENY] (Immediate)
              │ • Safe Read Whitelist (git status, ls)  ───►  │ ──► [ALLOW] (Immediate)
              └───────────────────────┬───────────────────────┘
                                      │ (Needs semantic judgment)
                                      ▼
                  ┌────────────────────────────────────────┐
                  │     TypeSafe AI (Jev API Evaluation)   │
                  │  • is_workspace_contained (Noul)       │
                  │  • destructive_potential (Score 0-3)   │
                  │  • violation_category (Choice)         │
                  └───────────────────┬────────────────────┘
                                      │
                                      ▼
                  ┌────────────────────────────────────────┐
                  │            Policy Evaluator            │
                  │  • Safe & Contained      ──► [ALLOW]   │
                  │  • Moderate / Outside    ──► [ASK]     │
                  │  • Catastrophic / Attack ──► [DENY]    │
                  │  • Network / API Error   ──► [ASK]     │
                  └───────────────────┬────────────────────┘
                                      │
                  ┌───────────────────┴────────────────────┐
                  │ Adapter Formatter: Exit Code & Output  │
                  │  Claude/Codex: stdout hookSpecificOutput│
                  │  Antigravity: stdout {"decision": ...} │
                  └────────────────────────────────────────┘
```

---

## Proposed Changes

### Core Binary (`pkg/` & `main.go`)

#### [NEW] [main.go](file:///c:/dev/jev-typesafeai/main.go)
- Entry point for `jev-guard`.
- Orchestrates stdin ingestion, adapter normalization, local fast-path check, Jev evaluation, policy resolution, and harness response formatting.

#### [NEW] [pkg/harness/types.go](file:///c:/dev/jev-typesafeai/pkg/harness/types.go)
- Data structures for incoming payloads:
  - Claude Code / Codex: `tool_name`, `tool_input`, `cwd`.
  - Antigravity: `toolCall` (`name`, `args`), `workspacePaths`, `conversationId`.
- Unified internal model: `NormalizedToolCall` (`ToolName`, `CommandOrTarget`, `Cwd`, `WorkspaceRoots`, `HarnessType`).

#### [NEW] [pkg/harness/adapter.go](file:///c:/dev/jev-typesafeai/pkg/harness/adapter.go)
- Auto-detects caller format from JSON shape.
- Formats final output:
  - Claude Code/Codex: Exit code `0` with `hookSpecificOutput` (`allow`/`ask`), or Exit code `2` with `stderr` (`deny`).
  - Antigravity: Exit code `0` with `{ "decision": "allow" | "ask" | "deny", "reason": "..." }`.

#### [NEW] [pkg/boundary/resolver.go](file:///c:/dev/jev-typesafeai/pkg/boundary/resolver.go)
- Authoritative workspace root resolution.
- Checks provided `workspacePaths` (Antigravity).
- Falls back to climbing parent directories from `cwd` to locate `.git`.
- Resolves relative path escapes (`../../`).

#### [NEW] [pkg/fastpath/filter.go](file:///c:/dev/jev-typesafeai/pkg/fastpath/filter.go)
- Zero-latency static evaluator (< 2ms):
  - **Sensitive Blacklist**: Directly triggers `ASK` for `.env*`, `*.pem`, `*.key`, `id_rsa`, `~/.ssh/*`, `~/.aws/*`, `credentials.json`.
  - **Safe Whitelist**: Directly triggers `ALLOW` for `ls`, `dir`, `git status`, `git diff`, `git log`, `pwd`, Antigravity `view_file`, `list_dir`, `grep_search`.
  - **Catastrophic Blacklist**: Directly triggers `DENY` for `rm -rf /`, `:(){ :|:& };:`, `format C:`.

#### [NEW] [pkg/evaluator/typesafe.go](file:///c:/dev/jev-typesafeai/pkg/evaluator/typesafe.go)
- Client for TypeSafe System One (Jev) API (`https://api.typesafe.ai/v1/evaluate`):
  - Builds payload with `state` (Workspace Root, Cwd, Tool Name, Command/Payload).
  - Sends 3-Primitive Decomposed Fan-out:
    - `is_workspace_contained` (`Noul`)
    - `destructive_potential` (`Score` with 4 descriptive levels: read-only -> reversible workspace edit -> environment/service change -> catastrophic/persistence)
    - `violation_category` (`Choice`)
  - Configurable HTTP timeout (default `1500ms`).

#### [NEW] [pkg/policy/evaluator.go](file:///c:/dev/jev-typesafeai/pkg/policy/evaluator.go)
- Deterministic decision policy:
  - **ALLOW**: `destructive_potential <= 1.2` AND `is_workspace_contained >= 0.85` AND `violation_category == "none"`.
  - **ASK**: `is_workspace_contained < 0.85` OR `1.2 < destructive_potential <= 2.5` OR API failure / timeout.
  - **DENY**: `destructive_potential > 2.5` OR self-modification/persistence attack.

#### [NEW] [pkg/config/config.go](file:///c:/dev/jev-typesafeai/pkg/config/config.go)
- Loads optional `.jevguard.json` and environment variables (`TYPESAFE_API_KEY`, `JEV_GUARD_MODE`, `JEV_GUARD_TIMEOUT_MS`).
- Supports `enforcing` vs `audit` mode.
- Appends audit decisions to `.jevguard.log` when enabled.

---

### Harness Configuration Templates & Manifests

#### [NEW] [.claude/hooks.json](file:///c:/dev/jev-typesafeai/.claude/hooks.json)
- Claude Code PreToolUse configuration matching `Bash|Edit|Write`.

#### [NEW] [.agents/hooks.json](file:///c:/dev/jev-typesafeai/.agents/hooks.json)
- Antigravity PreToolUse hook matching `run_command|write_to_file|replace_file_content`.

#### [NEW] [.codex/hooks.json](file:///c:/dev/jev-typesafeai/.codex/hooks.json)
- Codex CLI PreToolUse configuration matching `Bash|exec_command|apply_patch`.

#### [NEW] [.jevguard.json](file:///c:/dev/jev-typesafeai/.jevguard.json)
- Default project configuration template (sensitive file blacklist, allow paths, trusted domains).

---

### Distribution & Installation Scripts

#### [NEW] [install.sh](file:///c:/dev/jev-typesafeai/install.sh) & [install.ps1](file:///c:/dev/jev-typesafeai/install.ps1)
- Detects OS (Linux, macOS, Windows) and architecture (amd64, arm64).
- Downloads pre-built standalone binary from GitHub Releases (or builds locally if `go` is installed).
- Places binary in `~/.local/bin/` or `%USERPROFILE%\.local\bin\`.
- Supports `--global` and `--local` registration for Claude Code, Codex, and Antigravity.

#### [NEW] [.github/workflows/release.yml](file:///c:/dev/jev-typesafeai/.github/workflows/release.yml)
- Automated cross-compilation on tag push:
  - `jev-guard-linux-amd64`, `jev-guard-linux-arm64`
  - `jev-guard-darwin-amd64`, `jev-guard-darwin-arm64`
  - `jev-guard-windows-amd64.exe`

---

## Verification Plan

### Automated Unit & Mock Tests
- **Harness Adapter Tests** (`pkg/harness/adapter_test.go`):
  - Verify Claude Code payload produces valid `hookSpecificOutput` JSON.
  - Verify Antigravity payload produces valid `{ "decision": "...", "reason": "..." }` JSON.
- **Fast-Path & Sensitive File Tests** (`pkg/fastpath/filter_test.go`):
  - Verify `cat .env`, `type .env`, `rm .env` immediately return `ASK`.
  - Verify `ls -la`, `git status`, `view_file` immediately return `ALLOW` (< 2ms).
  - Verify `rm -rf /` immediately returns `DENY`.
- **Workspace Boundary Tests** (`pkg/boundary/resolver_test.go`):
  - Verify `../../outside` escapes are flagged as outside workspace.
  - Verify workspace paths from Antigravity are respected.
- **Mock TypeSafe Evaluator Tests** (`pkg/evaluator/typesafe_test.go`):
  - Mock HTTP test server responding with Jev Noul/Score/Choice responses.
  - Verify timeout and HTTP error fail-safe triggers `ASK` (fail interactive).
- **Policy Threshold Tests** (`pkg/policy/evaluator_test.go`):
  - Verify calibrated scores correctly transition between ALLOW, ASK, and DENY.

### Manual Verification
- Test running `jev-guard` with piped JSON from CLI simulating each agent.
- Test in Antigravity by triggering a simulated command through `.agents/hooks.json`.
