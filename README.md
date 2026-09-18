# jev-guard

High-speed, cross-agent safety gate plugin for **Claude Code**, **Codex CLI**, and **Antigravity**.

`jev-guard` intercepts tool calls (shell executions, file writes, patch applications) before execution, performs sub-millisecond local boundary and sensitive file checks, and utilizes **TypeSafe AI's System One (Jev)** model to evaluate blast radius, reversibility, and destructive potential.

---

## Key Features

- **Multi-Agent Interception**: Automatically detects and handles payload structures from Claude Code (`Bash`, `Edit`, `Write`), Codex CLI, and Antigravity (`run_command`, `write_to_file`, `replace_file_content`).
- **Sub-3ms Local Fast-Path**:
  - **Catastrophic Denylist**: Immediately rejects dangerous commands (`rm -rf /`, fork bombs, format disk).
  - **Sensitive File Protection**: Immediately prompts confirmation (`ASK`) for credentials, `.env*`, `.ssh/`, AWS keys, and private certificates.
  - **Safe Whitelist**: Zero-latency approval (`ALLOW`) for benign inspection commands (`git status`, `git diff`, `ls`, `dir`, `pwd`, `view_file`, `grep_search`).
- **TypeSafe AI (Jev) Semantic Evaluation**:
  - Ambiguous or mutating actions are dispatched in parallel to TypeSafe System One (`POST https://api.typesafe.ai/v1/systemone`).
  - Evaluates 3 primitives:
    1. `is_workspace_contained` (`Noul`): Probability the operation stays strictly inside workspace roots.
    2. `destructive_potential` (`Score` 0-3): Evaluates blast radius from trivial read-only to catastrophic deletion.
    3. `violation_category` (`Choice`): Identifies credential leaks, workspace escapes, or persistence attempts.
- **Fail-Safe Operation**: If TypeSafe AI is unavailable or network times out, safely falls back to interactive confirmation (`ASK`).

---

## Installation

### One-Line Install

#### Linux / macOS:
```bash
curl -fsSL https://raw.githubusercontent.com/typesafe-ai/jev-guard/main/install.sh | bash
```

#### Windows (PowerShell):
```powershell
irm https://raw.githubusercontent.com/typesafe-ai/jev-guard/main/install.ps1 | iex
```

---

## Configuration

Set your TypeSafe AI API key:
```bash
export TYPESAFE_API_KEY="your-typesafe-api-key"
```

Optional configuration via `.jevguard.json`:
```json
{
  "$schema": "https://typesafe.ai/schemas/jevguard.v1.json",
  "mode": "enforcing",
  "timeout_ms": 1500,
  "audit_log_path": ".jevguard.log",
  "sensitive_files": [
    ".env",
    "*.pem",
    "id_rsa"
  ],
  "trusted_commands": [
    "git status",
    "git log"
  ]
}
```

---

## Hook Setup

### Claude Code (`.claude/hooks.json`)
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Edit|Write",
        "command": "jev-guard"
      }
    ]
  }
}
```

### Antigravity (`.agents/hooks.json`)
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "run_command|write_to_file|replace_file_content",
        "command": "jev-guard"
      }
    ]
  }
}
```

### Codex CLI (`.codex/hooks.json`)
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|exec_command|apply_patch",
        "command": "jev-guard"
      }
    ]
  }
}
```

---

## Development & Testing

```bash
# Run all unit tests
go test -v ./...

# Build binary locally
go build -o jev-guard main.go
```

---

## License

MIT
