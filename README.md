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
  - **Sensitive File Protection**: Immediately prompts confirmation for credentials, `.env*`, `.ssh/`, AWS keys, and private certificates before network calls.
  - **Workspace Boundary Enforcement**: Resolves path traversals and directory escapes (`../../`) locally across write and read operations (preventing unauthorized access or exfiltration of files outside workspace boundaries such as `/etc/shadow` or `C:\Windows\system.ini`).
  - **Trusted Command & Read Tool Cache**: Zero-latency approval (`ALLOW`) for safe read inspection tools and trusted shell inspection commands (`git status`, `git diff`, `git log`, `ls`, `dir`, `pwd`, etc.) once boundary and sensitive file checks pass.
  - **Bypass Toggle**: Fully configurable via `"fastpath_enabled": false` or `JEV_GUARD_FASTPATH_ENABLED=0` to route 100% of operations directly to Jev.
- **Platform-Specific Safety Enforcement**:
  - **Antigravity Human Escalation via `force_ask`**: Maps confirmation decisions to `force_ask` in Antigravity hook responses, ensuring guaranteed human operator review by overriding Antigravity's auto-execution and turbo cache. Emits `permissionOverrides: ["command(...)"]` to streamline approved actions.
  - **Claude Code & Codex Fail-Safe Blocking**: In Claude Code and Codex, autonomous/bypass flags (`--dangerously-skip-permissions`, `--yolo`, headless `-p`) disable interactive prompts. `jev-guard` enforces safety by defaulting all `ASK` and `force_ask` escalations to **exit code 2** (rejection with feedback to `stderr`), preventing sensitive files or boundary escapes from silently executing.
- **Flexible Operating Modes**:
  - **`enforcing`** (default): Actively enforces policy verdicts—blocking catastrophic commands (`DENY`), prompting confirmation for sensitive or moderate operations (`force_ask` in Antigravity, exit code 2 in Claude/Codex), and approving verified actions (`ALLOW`).
  - **`audit`**: Passive monitoring dry-run. Logs every tool call and evaluation result to `.jevguard.log`, but rewrites blocking decisions to `ALLOW` (`[AUDIT-MODE: <decision>]`) so agent workflows are never interrupted.
- **TypeSafe AI (Jev) Semantic & Catastrophic Evaluation**:
  - Eliminates brittle command-line regex matching. All mutating, destructive, or ambiguous operations are evaluated by TypeSafe System One (`POST https://api.typesafe.ai/v1/systemone`).
  - Evaluates 3 primitives:
    1. `is_workspace_contained` (`Noul`): Probability the operation stays strictly inside workspace roots.
    2. `destructive_potential` (`Score` 0-3): Evaluates blast radius from trivial read-only to catastrophic deletion.
    3. `violation_category` (`Choice`): Identifies credential leaks, workspace escapes, or persistence attempts.
- **Fail-Safe Operation**: If TypeSafe AI is unavailable or network times out, safely falls back to interactive confirmation (`ASK` / `force_ask`).

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

### Operating Modes

`jev-guard` supports two operational modes configured via `"mode"` in `.jevguard.json` or the `JEV_GUARD_MODE` environment variable:

- **`enforcing`** (default): Active safety gating.
  - Catastrophic operations or security violations are blocked (`DENY` / exit code 2).
  - Sensitive file accesses, boundary escapes, or moderate risk operations trigger safety escalation:
    - **Antigravity**: Emits `"force_ask"` on stdout with `permissionOverrides`, guaranteeing an interactive approval modal even in Turbo Mode.
    - **Claude Code & Codex**: Exits with **code 2** (hard block with reason on `stderr`), preventing bypass flags (`--dangerously-skip-permissions`, `--yolo`, headless `-p`) from silently executing unconfirmed actions.
  - Safe, contained operations are permitted (`ALLOW` / exit code 0).
- **`audit`**: Passive evaluation and dry-run monitoring.
  - All operations are processed through fastpath and TypeSafe AI semantic evaluation.
  - Full evaluation telemetry is written to `.jevguard.log`.
  - All `DENY`, `ASK`, and `force_ask` decisions are converted to `ALLOW` with an `[AUDIT-MODE: <decision>]` reason prefix, ensuring zero interruption to agent workflows while capturing telemetry.

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

### Recommended `.gitignore` Entries

To protect your TypeSafe AI credentials and prevent committing local telemetry logs, add the following to your project's `.gitignore`:

```gitignore
# jev-guard configuration (contains private API key) & audit logs
.jevguard.json
jevguard.json
.jevguard.log
*.jevguard.log
```

### Settings & Environment Variables Reference

| Setting | Configuration Key | Environment Variable | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Mode** | `mode` | `JEV_GUARD_MODE` | `"enforcing"` | Operational mode: `"enforcing"` or `"audit"` |
| **API Key** | `typesafe_api_key` / `api_key` | `TYPESAFE_API_KEY` | `""` | TypeSafe AI API key |
| **Base URL** | `base_url` | `TYPESAFE_API_URL` | `"https://api.typesafe.ai"` | TypeSafe API endpoint URL |
| **Model** | `model` | `TYPESAFE_MODEL` | `"jev-latest"` | System One evaluation model |
| **Timeout** | `timeout_ms` | `JEV_GUARD_TIMEOUT_MS` | `1500` | Evaluation HTTP timeout in milliseconds |
| **Fastpath** | `fastpath_enabled` | `JEV_GUARD_FASTPATH_ENABLED` | `true` | Enable sub-1ms local fastpath filter |
| **Audit Log** | `audit_log_path` | — | `""` | Destination path for JSONL audit logging |
| **Sensitive Files** | `sensitive_files` | — | *(built-in defaults)* | Array of substrings/globs to prompt confirmation on |
| **Trusted Commands** | `trusted_commands` | — | *(built-in defaults)* | Array of command prefixes cached for zero-latency approval |

### Configuration Precedence

1. **Environment Variables** (`TYPESAFE_API_KEY`, `TYPESAFE_API_URL`, `TYPESAFE_MODEL`, `JEV_GUARD_MODE`, `JEV_GUARD_TIMEOUT_MS`, `JEV_GUARD_FASTPATH_ENABLED`) override file settings.
2. **Project Configuration** (`.jevguard.json` or `jevguard.json` discovered in `cwd` or nearest ancestor directory).
3. **Built-in Defaults** (`mode: "enforcing"`, `timeout_ms: 1500`, `fastpath_enabled: true`, standard sensitive file patterns and read commands).

### Audit Log Schema

When `"audit_log_path"` is configured, every tool evaluation produces a JSONL entry:

```json
{
  "timestamp": "2026-09-18T12:00:00Z",
  "tool_name": "run_command",
  "command": "git diff .env",
  "target_path": "",
  "decision": "force_ask",
  "reason": "Access to sensitive file or credential pattern: .env",
  "source": "fastpath_sensitive",
  "confidence": 1.0
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

### Platform Safety & Autonomous Matrix

When running agents in autonomous, turbo, or bypass modes, `jev-guard` maintains strict invariants according to each harness's hook protocol:

| Verdict | Antigravity (Turbo / `always-proceed`) | Claude Code (`--dangerously-skip-permissions`) | Codex CLI (`--yolo` / `approval_policy = "never"`) |
| :--- | :--- | :--- | :--- |
| **`ALLOW`** | Auto-proceeds (`"allow"`) | Auto-proceeds (Exit `0`) | Auto-proceeds (Exit `0`) |
| **`ASK` / Sensitive / Escape** | **Halts & Prompts User** (`"force_ask"` overrides cache) | **Fails Safe & Blocks** (Exit `2` with `stderr` feedback) | **Fails Safe & Blocks** (Exit `2` with `stderr` feedback) |
| **`DENY` / Catastrophic** | **Hard Block** (`"deny"`) | **Hard Block** (Exit `2`) | **Hard Block** (Exit `2`) |

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

