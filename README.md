# jev-guard

High-speed, cross-agent safety gate plugin for **Claude Code**, **Codex CLI**, and **Antigravity**.

`jev-guard` intercepts tool calls (shell executions, file writes, patch applications, file reads, and directory inspections) before execution, performs sub-millisecond local boundary and sensitive file checks, and utilizes **TypeSafe AI's System One (Jev)** model to evaluate blast radius, reversibility, and destructive potential.

---

## Key Features

- **Multi-Agent Interception**: Automatically detects and handles payload structures from:
  - **Claude Code**: `Bash`, `Edit`, `Write`, `View`, `ReadLocalFile`, `LS`, `Grep`, `Glob`
  - **Antigravity**: `run_command`, `write_to_file`, `replace_file_content`, `view_file`, `list_dir`, `grep_search`, `find_by_name`, `read_resource`, `read_url_content`
  - **Codex CLI**: `Bash`, `exec_command`, `apply_patch`, `view_file`, `read_file`, `list_dir`
- **Sub-1ms Local Invariant & Latency Gate**:
  - **Sensitive File Protection**: Immediately prompts confirmation (`ASK`) for credentials, `.env*`, `.ssh/`, AWS keys, and private certificates before network calls.
  - **Workspace Boundary Enforcement**: Resolves path traversals and directory escapes (`../../`) locally across write and read operations (preventing unauthorized access or exfiltration of files outside workspace boundaries such as `/etc/shadow` or `C:\Windows\system.ini`).
  - **Trusted Command & Read Tool Cache**: Zero-latency approval (`ALLOW`) for safe read inspection tools and trusted shell inspection commands (`git status`, `git diff`, `git log`, `ls`, `dir`, `pwd`, etc.) once boundary and sensitive file checks pass.
  - **Bypass Toggle**: Fully configurable via `"fastpath_enabled": false` or `JEV_GUARD_FASTPATH_ENABLED=0` to route 100% of operations directly to Jev.
- **Antigravity Permission Overrides**: Returns `permissionOverrides: ["command(...)"]` on approved (`ALLOW`) and user-confirmed (`ASK`) command executions, eliminating redundant permission prompts in the Antigravity UI.
- **TypeSafe AI (Jev) Semantic & Catastrophic Evaluation**:
  - Eliminates brittle command-line regex matching. All mutating, destructive, or ambiguous operations are evaluated by TypeSafe System One (`POST https://api.typesafe.ai/v1/systemone`).
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

## CLI Usage & Verification

`jev-guard` includes built-in flags for diagnostics and supports manual payload testing via standard input:

```bash
# Display version and build information
jev-guard --version

# Show help and usage details
jev-guard --help

# Test evaluation manually by piping a tool call payload JSON
cat payload.json | jev-guard
```

> [!NOTE]
> When executed directly in an interactive terminal without piped input or flags, `jev-guard` displays help and usage guidance instead of blocking on stdin.

---

## Configuration

### Hierarchical Configuration Discovery

`jev-guard` searches for `.jevguard.json` or `jevguard.json` by inspecting the tool call's working directory (`cwd`), workspace roots, and target file directory, automatically traversing up ancestor directories until a configuration file is found. This allows subdirectories and monorepo packages to automatically inherit the workspace root configuration without duplicate config files.

```text
my-project/
├── .jevguard.json          # Root safety policy & settings (inherited by subdirectories)
├── .jevguard.log           # Anchored audit log (if audit_log_path is configured)
├── packages/
│   └── app/                # Commands run here automatically inherit root .jevguard.json
└── ...
```

Relative audit log paths (such as `"audit_log_path": ".jevguard.log"`) are automatically anchored to the directory containing the resolved configuration file, ensuring audit entries are centralized in a single log rather than split across child directories.

### Configuration Options

You can configure your TypeSafe AI API key either via environment variable:
```bash
export TYPESAFE_API_KEY="your-typesafe-api-key"
```

Or directly inside `.jevguard.json` (using `"typesafe_api_key"` or `"api_key"`) along with optional policy parameters:
```json
{
  "mode": "enforcing",
  "typesafe_api_key": "your-typesafe-api-key",
  "timeout_ms": 1500,
  "model": "jev-latest",
  "fastpath_enabled": true,
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

1. **Environment Variables** (`TYPESAFE_API_KEY`, `TYPESAFE_API_URL`, `TYPESAFE_MODEL`, `JEV_GUARD_MODE`, `JEV_GUARD_TIMEOUT_MS`, `JEV_GUARD_FASTPATH_ENABLED`) override file settings.
2. **Project Configuration** (`.jevguard.json` or `jevguard.json` discovered in `cwd` or nearest ancestor directory).
3. **Built-in Defaults** (`mode: "enforcing"`, `timeout_ms: 1500`, `fastpath_enabled: true`, standard sensitive file patterns and read commands).

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
  "jev-guard": {
    "PreToolUse": [
      {
        "matcher": "run_command|write_to_file|replace_file_content|view_file|list_dir|grep_search|find_by_name|read_resource",
        "hooks": [
          {
            "type": "command",
            "command": "jev-guard"
          }
        ]
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

