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

### Local Installation

Build and install directly to your local user binary directory:

#### Linux / macOS:
```bash
./install.sh
```

#### Windows (PowerShell):
```powershell
.\install.ps1
```

---

## Configuration

### File Location

Place `.jevguard.json` directly in the **root of your project or workspace** (the working directory `cwd` where your AI agent—Claude Code, Codex, or Antigravity—is launched and runs commands):

```text
my-project/
├── .jevguard.json          # Project-specific safety policy & settings
├── .jevguard.log           # Generated audit log (if audit_log_path is configured)
├── ...
```

`jev-guard` dynamically checks for `.jevguard.json` inside the tool call's working directory (`cwd`) for each intercepted action.

### Configuration Options

You can configure your TypeSafe AI API key either via environment variable:
```bash
export TYPESAFE_API_KEY="your-typesafe-api-key"
```

Or directly inside `.jevguard.json` along with optional policy parameters:
```json
{
  "mode": "enforcing",
  "typesafe_api_key": "your-typesafe-api-key",
  "timeout_ms": 1500,
  "model": "jev-latest",
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

> [!TIP]
> If you embed `typesafe_api_key` inside `.jevguard.json`, remember to add `.jevguard.json` and `.jevguard.log` to your `.gitignore`, or configure `TYPESAFE_API_KEY` globally as an environment variable instead.

### Configuration Precedence

1. **Environment Variables** (`TYPESAFE_API_KEY`, `TYPESAFE_API_URL`, `TYPESAFE_MODEL`, `JEV_GUARD_MODE`, `JEV_GUARD_TIMEOUT_MS`) override file settings.
2. **Project Configuration** (`.jevguard.json` located in the project root / `cwd`).
3. **Built-in Defaults** (`mode: "enforcing"`, `timeout_ms: 1500`).

---

## Hook Setup

### Claude Code (`.claude/hooks.json`)
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Edit|Write|View|ReadLocalFile|LS|Grep|Glob",
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
        "matcher": "run_command|write_to_file|replace_file_content|view_file|list_dir|grep_search|find_by_name|read_resource",
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
        "matcher": "Bash|exec_command|apply_patch|view_file|read_file|list_dir",
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
