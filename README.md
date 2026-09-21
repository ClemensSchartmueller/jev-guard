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
  - **Trusted Command & Read Tool Cache**: Zero-latency approval (`ALLOW`) for safe local read inspection tools and trusted shell inspection commands (`git status`, `git diff`, `git log`, `ls`, `dir`, `pwd`, etc.) once boundary and sensitive file checks pass. Chained commands (using `;`, `&&`, `&`, `|`, `>`, or newlines) and outbound network fetch operations (`read_url_content`) are strictly routed to TypeSafe AI System One for semantic evaluation.
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
- **Context-Aware Intent Authorization & Ephemeral Cache (Fully Optional)**:
  - **User Intent Ingestion**: Ingests active user prompts via dedicated lifecycle hooks (`UserPromptSubmit` in Claude Code, `PreInvocation` in Antigravity) into an ephemeral session cache stored in `~/.jevguard/sessions/`.
  - **Zero False-Positive Confirmations**: When the human operator explicitly requests an action (e.g. *"Delete the build directory"* or *"Set PORT=3000 in .env"*), TypeSafe AI confirms intent alignment and auto-approves (`ALLOW`), removing repetitive interactive prompts.
  - **Strict Catastrophic Ceiling**: Even with proven intent, catastrophic deletions or unbounded disk destruction (`destructive_potential > 2.5`) **cap at `force_ask`**, never `ALLOW`, guaranteeing human oversight for dangerous actions.
  - **Anti-Tampering Invariants**: `~/.jevguard` is physically decoupled from project workspaces, and fastpath immediately denies any tool call attempting to read, write, or modify session cache files.
  - **Fully Optional & Zero-Guess Fallback**: Configurable via `"context_awareness_enabled": false` or `JEV_GUARD_CONTEXT_AWARENESS_ENABLED=0`. If the cache is cold, `jev-guard` falls back deterministically to strict stateless safety.
- **Fail-Safe Operation**: If TypeSafe AI is unavailable or network times out, safely falls back to interactive confirmation (`ASK` / `force_ask`).

---

## Directory Architecture (`~/.jevguard`)

`jev-guard` maintains a unified, self-contained directory in your user home:

```text
~/.jevguard/
├── bin/
│   └── jev-guard (or jev-guard.exe)   # Executable binary (added to User PATH)
├── sessions/
│   └── <session_hash>.json            # Ephemeral, atomic session intent cache
└── logs/
    └── audit.log                      # Optional fallback audit log
```

## Installation

### Prebuilt Binaries

Download precompiled binaries for Linux, macOS, and Windows from the [GitHub Releases](https://github.com/ClemensSchartmueller/jev-guard/releases) page. Each release includes SHA256 checksums in `checksums.txt`.

### Local Installation

Build and install directly to `~/.jevguard/bin` (automatically configured in your User `PATH`):

#### Linux / macOS:
```bash
./install.sh
```

#### Windows (PowerShell):
```powershell
.\install.ps1
```

---

## CLI Usage & Commands

`jev-guard` includes subcommands for intent management, diagnostics, and testing:

```bash
# Display version and build information
jev-guard --version

# Show help and command reference
jev-guard --help

# Ingest active user prompt/intent into the session cache (supports space-separated or --flag=value)
jev-guard ingest --session "my-session" --turn 1 --prompt "Delete the build folder"
jev-guard ingest --session="my-session" --turn=1 --prompt="Delete the build folder"

# Or pipe a hook event JSON payload directly on stdin
cat hook_payload.json | jev-guard ingest

# Clear active intent for a specific session (or all sessions)
jev-guard clear-intent --session "my-session"
jev-guard clear-intent --session="my-session"
jev-guard clear-intent --all
jev-guard cache clear

# Display status of active sessions and cache directory
jev-guard status

# Test gate evaluation manually by piping a tool call payload JSON
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
  "context_awareness_enabled": true,
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
| **Context Awareness** | `context_awareness_enabled` | `JEV_GUARD_CONTEXT_AWARENESS_ENABLED` | `true` | Enable session intent caching & intent-aware evaluation |
| **Audit Log** | `audit_log_path` | — | `""` | Destination path for JSONL audit logging |
| **Sensitive Files** | `sensitive_files` | — | *(built-in defaults)* | Array of substrings/globs to prompt confirmation on |
| **Trusted Commands** | `trusted_commands` | — | *(built-in defaults)* | Array of command prefixes cached for zero-latency approval |

### Configuration Precedence

1. **Environment Variables** (`TYPESAFE_API_KEY`, `TYPESAFE_API_URL`, `TYPESAFE_MODEL`, `JEV_GUARD_MODE`, `JEV_GUARD_TIMEOUT_MS`, `JEV_GUARD_FASTPATH_ENABLED`, `JEV_GUARD_CONTEXT_AWARENESS_ENABLED`) override file settings.
2. **Project Configuration** (`.jevguard.json` or `jevguard.json` discovered in `cwd` or nearest ancestor directory).
3. **Built-in Defaults** (`mode: "enforcing"`, `timeout_ms: 1500`, `fastpath_enabled: true`, `context_awareness_enabled: true`, standard sensitive file patterns and read commands).

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

Configure `UserPromptSubmit` to ingest human instructions into the session cache, and `PreToolUse` to enforce safety:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "matcher": ".*",
        "command": "jev-guard ingest"
      }
    ],
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

Configure `PreInvocation` to capture turn intent and `PreToolUse` for tool-level gating:

```json
{
  "jev-guard": {
    "PreInvocation": [
      {
        "type": "command",
        "command": "jev-guard ingest"
      }
    ],
    "PreToolUse": [
      {
        "matcher": "run_command|write_to_file|replace_file_content|view_file|list_dir|grep_search|find_by_name|read_resource|read_url_content",
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

## Context-Aware Intent Policy Matrix

When context awareness is enabled and intent is ingested, TypeSafe AI classifies `intent_alignment` into three categories:

| Action Risk / Blast Radius | Unprompted / Contrary Intent | Incidental / Unclear Intent | Explicitly Requested by User |
| :--- | :--- | :--- | :--- |
| **Catastrophic Deletion** (`score > 2.5`, `catastrophic_deletion`) | **DENY** (Hard block) | **DENY** (Hard block) | **`force_ask`** (Mandatory interactive confirmation) |
| **Moderate Blast Radius** (`score 1.2 – 2.4`, e.g. `rm -rf dist`) | **`force_ask`** (Confirmation) | **`force_ask`** (Confirmation) | **`ALLOW`** (Auto-proceeds frictionlessly) |
| **Sensitive File Access** (`.env`, `.pem`, credentials) | **`force_ask`** (Confirmation) | **`force_ask`** (Confirmation) | **`ALLOW`** (Auto-proceeds frictionlessly) |
| **Privilege / Persistence** (system profile edits, root escalations) | **DENY** (Hard block) | **DENY** (Hard block) | **`force_ask`** (Mandatory confirmation) |
| **Workspace Boundary Escape** (`../../` traversal) | **`force_ask`** (Confirmation) | **`force_ask`** (Confirmation) | **`force_ask`** (Confirmation) |
| **Anti-Tampering** (`~/.jevguard/` cache access) | **DENY** (Strict invariant) | **DENY** (Strict invariant) | **DENY** (Strict invariant) |

> [!IMPORTANT]
> **The Catastrophic Ceiling**: Even when explicitly commanded by the user, actions with catastrophic blast radius (e.g. `rm -rf /` or recursive drive formatting) **never auto-execute**. `jev-guard` downgrades them from a hard `DENY` to an interactive confirmation prompt (`force_ask`), giving human operators the final veto. This catastrophic invariant takes precedence over all violation categories (including credential access).
>
> In addition, explicit authorization requires high confidence from TypeSafe AI (`intent_confidence >= 0.70`); lower-confidence classifications safely fall back to interactive confirmation (`force_ask` / `ASK`). Fastpath strictly defers all sensitive file accesses (`.env`, `.pem`, etc.) to semantic evaluation when user intent is active, preventing read tools or trusted command caches from prematurely auto-allowing access.

---

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

## Contributing

Contributions are welcome! Whether it is extending harness support, refining detection heuristics, improving TypeSafe System One prompt templates, or reporting issues, community feedback and pull requests are greatly appreciated.

---

## Disclaimer

This software is provided "as is", without warranty of any kind, express or implied. Neither TypeSafe AI (`typesafe.ai`), the `jev-guard` project, nor its contributors or maintainers are liable for any damages, losses, or claims arising from the use or performance of this hook (including, but not limited to, damages caused by misclassifications, false positives, or false negatives from Jev AI / TypeSafe AI). Users are responsible for evaluating and supervising automated agent tool calls in their own environments.

---

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

