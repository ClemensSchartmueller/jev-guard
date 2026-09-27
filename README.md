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
  - **Sensitive File Protection**: Immediately prompts confirmation for credentials, `.env*`, `.ssh/`, `.aws/`, `.kube/`, `kubeconfig`, `.npmrc`, `.yarnrc`, `.pypirc`, `.git-credentials`, `id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa`, and private certificates before network calls. Normalizes both POSIX (`/`) and Windows (`\`) path separators for consistent matching across OS environments.
  - **Workspace Boundary Enforcement**: Resolves path traversals and directory escapes (`../../`) locally across write and read operations (preventing unauthorized access or exfiltration of files outside workspace boundaries such as `/etc/shadow` or `C:\Windows\system.ini`). Preserves path case sensitivity on Linux while performing case-insensitive matching on Windows. Enforces fail-closed containment on path resolution errors.
  - **Anti-Tampering Invariants**: Direct access, reads, writes, or modifications targeting `.jevguard.json`, `jevguard.json`, `.jevguard.log`, or `~/.jevguard/` are strictly blocked (`DENY`) to prevent secret exposure or policy tampering.
  - **Trusted Command & Read Tool Cache**: Zero-latency approval (`ALLOW`) for safe local read inspection tools and trusted shell inspection commands (`git status`, `git diff`, `git log`, `ls`, `dir`, `pwd`, etc.) once boundary, command flag arguments, and sensitive file checks pass. Chained commands (using `;`, `&&`, `&`, `|`, `>`, `<`, or newlines), PowerShell subexpression operators (`(`, `)`, `{`, `}`, `$`, `@(`), and outbound network fetch operations (`read_url_content`) are strictly routed to TypeSafe AI System One for semantic evaluation.
  - **User-controlled Bypass Toggle**: Set `"fastpath_enabled": false` in `~/.jevguard/config.json` to route operations directly to Jev.
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
  - **User Intent Ingestion**: Ingests active user prompts from Claude Code's `UserPromptSubmit` hook into an ephemeral session cache stored in `~/.jevguard/sessions/`. Antigravity's documented hook payload does not include prompt text, so its generated hooks use stateless tool-level gating.
  - **Zero False-Positive Confirmations**: When the human operator explicitly requests an action (e.g. *"Delete the build directory"* or *"Set PORT=3000 in .env"*), TypeSafe AI confirms intent alignment and auto-approves (`ALLOW`), removing repetitive interactive prompts.
  - **Strict Catastrophic Ceiling**: Even with proven intent, catastrophic deletions or unbounded disk destruction (`destructive_potential > 2.5`) **cap at `force_ask`**, never `ALLOW`, guaranteeing human oversight for dangerous actions.
  - **Anti-Tampering Invariants**: `~/.jevguard` is physically decoupled from project workspaces, and fastpath immediately denies any tool call attempting to read, write, or modify session cache files.
  - **Fully Optional & Zero-Guess Fallback**: Set `"context_awareness_enabled": false` in `~/.jevguard/config.json`. If the cache is cold, `jev-guard` falls back deterministically to strict stateless safety.
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

### One-command setup (Node.js and npm)

From the project you want to protect, run:

```bash
npx --yes jev-guard@latest
```

The npm launcher downloads the matching `jev-guard` release for your operating system and architecture, checks its SHA256 digest against the release checksums, installs it under `~/.jevguard/bin`, and runs `jev-guard init`. Setup adds hooks for detected agents in the current project; when none are detected, it sets up all supported agents. Existing hook configuration is preserved, and running setup again does not add duplicate hooks. The hooks call the installed binary by its absolute path, so they do not depend on a new terminal picking up a changed `PATH`.

To choose an agent explicitly, pass `--agent claude`, `--agent codex`, `--agent antigravity`, or `--agent all` after the package name. The default scope is the current project; `--scope user` configures supported user-level hooks. You can also run `jev-guard init` after installing a binary by another method.

The release tag and npm package version must match (for example, package `0.2.0` downloads release `v0.2.0`). The npm command becomes available after the first package is published. Node.js and npm are only needed for this setup route; the installed hooks run the native binary.

Set a TypeSafe AI API key before using semantic evaluation:

```bash
export TYPESAFE_API_KEY="your-typesafe-api-key" # Linux / macOS
```

```powershell
$env:TYPESAFE_API_KEY = "your-typesafe-api-key" # PowerShell, current session
```

Run `~/.jevguard/bin/jev-guard config show` (or `%USERPROFILE%\.jevguard\bin\jev-guard.exe config show` on Windows) to check policy and API key status. For Codex project hooks, review and trust the new hook through `/hooks` in Codex before it runs.

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
jev-guard cache status
jev-guard cache

# Test gate evaluation manually by piping a tool call payload JSON
cat payload.json | jev-guard
```

> [!NOTE]
> When executed directly in an interactive terminal without piped input or flags, `jev-guard` displays help and usage guidance instead of blocking on stdin.

---

## Configuration

### User-owned security settings

Security settings are read from `~/.jevguard/config.json` (on Windows, `%USERPROFILE%\.jevguard\config.json`). This file owns the enforcement mode, API endpoint, model, timeout, API key, audit log path, fastpath, context awareness, sensitive-file patterns, and trusted commands. Set `mode` to `audit` only when you intend blocking results to become `ALLOW`.

Repository files named `.jevguard.json` or `jevguard.json` are ignored until their exact contents are explicitly trusted. Even after trust, only additive `sensitive_files` entries are applied. Project values for `mode`, `base_url`, API keys, `fastpath_enabled`, `context_awareness_enabled`, and `trusted_commands` are ignored. Discovery checks the tool call's working directory and walks up to the nearest declared workspace root, inclusive. It also checks declared workspace roots directly. If no workspace root contains the working directory, discovery is bounded by the nearest `.git` directory or file; without one, it checks only the candidate directory. When a hook payload has neither a working directory nor workspace roots, the process working directory is the fallback and uses the same bounds. Target file directories are never used for config discovery.

Relative `audit_log_path` values in the user config are anchored to `~/.jevguard`, outside the project tree.

Use the CLI to inspect effective values and prepare or revoke a trust record:

```text
jev-guard config show
jev-guard config trust .jevguard.json
jev-guard config untrust .jevguard.json
```

`config trust` prints the file's canonical path, root, SHA-256 digest, supported settings, and the registry entry to review. It does not grant trust. To approve it, manually add that entry to `~/.jevguard/trusted-project-configs.json`:

```json
{
  "version": 1,
  "entries": [
    {
      "project_root": "/path/to/project",
      "config_path": "/path/to/project/.jevguard.json",
      "sha256": "digest-printed-by-config-trust"
    }
  ]
}
```

The digest is checked on every invocation. Editing or replacing the config requires a new reviewed record. `config untrust` identifies the user-owned registry entry to remove. The CLI does not write trust approvals because a confirmation typed into an agent-controlled shell would not prove that the user reviewed them. This design assumes the agent process cannot write `~/.jevguard/config.json` or `~/.jevguard/trusted-project-configs.json`. If an agent can run arbitrary commands with the same filesystem access as the user, manual approval text and file ownership alone cannot enforce that boundary; protect those files with an OS or product-level permission boundary outside the agent's writable paths.

### Operating Modes

`jev-guard` supports two operational modes configured via `"mode"` in the user-owned config:

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

Create `~/.jevguard/config.json` for user-owned settings. The API key can be supplied there or through the credential-only environment variable:
```bash
export TYPESAFE_API_KEY="your-typesafe-api-key"
```

Example user config:
```json
{
  "mode": "enforcing",
  "base_url": "https://api.typesafe.ai/v1/systemone",
  "api_key": "your-typesafe-api-key",
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

The endpoint must use HTTPS. HTTP is accepted only for localhost or loopback IPs. API requests do not follow redirects. `TYPESAFE_API_KEY` supplies credentials; environment variables cannot change mode, endpoint, model, timeout, or other policy settings.

### Recommended `.gitignore` Entries

To protect your TypeSafe AI credentials and prevent committing local telemetry logs, add the following to your project's `.gitignore`:

```gitignore
# Optional project additions and local audit logs
.jevguard.log
*.jevguard.log
```

### Settings & Environment Variables Reference

| Setting | Configuration Key | Environment Variable | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Mode** | `mode` | — | `"enforcing"` | Operational mode: `"enforcing"` or `"audit"` |
| **API Key** | `api_key` / `typesafe_api_key` | `TYPESAFE_API_KEY` | `""` | TypeSafe AI API key |
| **Base URL** | `base_url` | — | TypeSafe API default | HTTPS endpoint, or loopback HTTP endpoint |
| **Model** | `model` | — | `"jev-latest"` | System One evaluation model |
| **Timeout** | `timeout_ms` | — | `1500` | Evaluation HTTP timeout in milliseconds |
| **Fastpath** | `fastpath_enabled` | — | `true` | Enable sub-1ms local fastpath filter |
| **Context Awareness** | `context_awareness_enabled` | — | `true` | Enable session intent caching & intent-aware evaluation |
| **Audit Log** | `audit_log_path` | — | `""` | Destination path for JSONL audit logging |
| **Sensitive Files** | `sensitive_files` | — | *(built-in defaults)* | User config adds patterns; trusted project config can only add more |
| **Trusted Commands** | `trusted_commands` | — | *(built-in defaults)* | User-owned command prefixes cached for zero-latency approval |

### Configuration Precedence

1. **User config** (`~/.jevguard/config.json`) owns policy and endpoint settings.
2. **Credential environment variable** (`TYPESAFE_API_KEY`) supplies the API key.
3. **Trusted project config** can add `sensitive_files` only when the canonical path and exact SHA-256 digest match the user trust registry.
4. **Built-in defaults** include `mode: "enforcing"`, `timeout_ms: 1500`, `fastpath_enabled: true`, `context_awareness_enabled: true`, standard sensitive file patterns, and read commands.

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

### Claude Code (`.claude/settings.json`)

Configure hooks inside `.claude/settings.json` (workspace) or `~/.claude/settings.json` (global). Configure `UserPromptSubmit` to ingest human instructions into the session cache, and `PreToolUse` to enforce safety:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "jev-guard ingest"
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Bash|Edit|Write|View|ReadLocalFile|LS|Grep|Glob",
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

> [!NOTE]
> `jev-guard` formats Claude Code PreToolUse verdicts using the standard `hookSpecificOutput.permissionDecision` schema. Ingest confirmations are sent to `stderr` to ensure they never pollute active user prompts.

### Antigravity (`.agents/hooks.json`)

Configure `PreToolUse` for tool-level gating:

Antigravity's documented `PreInvocation` payload includes a transcript path but does not include the prompt text or document the transcript JSONL format. `jev-guard init --agent antigravity` therefore installs stateless tool gates and removes any older managed `PreInvocation` ingest hook. Prompt-bearing payloads remain supported by the explicit `jev-guard ingest` command.

```json
{
  "jev-guard": {
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

Codex loads this project hook only when the project is trusted. Run `/hooks` in the Codex CLI to review and trust the current hook definition before it can run; editing the hook requires a new review.

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

