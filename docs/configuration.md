# Configuration

- [Where settings live](#where-settings-live)
- [Example config](#example-config)
- [Settings reference](#settings-reference)
- [Operating modes](#operating-modes)
- [Precedence](#precedence)
- [Project configs and trust](#project-configs-and-trust)
- [Audit log](#audit-log)
- [Recommended `.gitignore` entries](#recommended-gitignore-entries)

## Where settings live

Security settings are read only from `~/.jevguard/.jevguard.json` (on Windows, `%USERPROFILE%\.jevguard\.jevguard.json`). The executable creates this file with enforcing defaults when it is missing and never overwrites an existing file. If creation fails, it reports the error and exits without evaluating the tool call.

The generated file contains `mode`, `timeout_ms`, `fastpath_enabled`, `context_awareness_enabled`, `intent_ttl_minutes`, and the full built-in `sensitive_files` and `trusted_commands` lists. Entries in `sensitive_files` and `trusted_commands` are always merged with the built-in defaults, so defaults cannot be removed.

The same directory holds the binary, trust registry, and session data:

```text
~/
└── .jevguard/
    ├── .jevguard.json                    # User-owned security settings
    ├── bin/
    │   └── jev-guard (or jev-guard.exe)  # Executable binary (install.ps1 adds this to User PATH)
    ├── sessions/
    │   └── <session_hash>.json           # Ephemeral, atomic session intent cache
    └── trusted-project-configs.json      # Approved project config digests, if configured
```

Run `jev-guard config show` to see the effective values and where each comes from. Secrets are never printed.

## Example config

```json
{
  "mode": "enforcing",
  "base_url": "https://api.typesafe.ai/v1/systemone",
  "api_key": "your-typesafe-api-key",
  "timeout_ms": 1500,
  "model": "jev-latest",
  "fastpath_enabled": true,
  "context_awareness_enabled": true,
  "intent_ttl_minutes": 30,
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

Instead of `api_key`, you can supply the key through the environment:

```bash
export TYPESAFE_API_KEY="your-typesafe-api-key"
```

`TYPESAFE_API_KEY` supplies credentials only; environment variables cannot change the mode, endpoint, model, timeout, or any other policy setting.

The endpoint must use HTTPS. HTTP is accepted only for localhost or loopback IPs. The URL must not contain credentials, a query string, or a fragment. API requests do not follow redirects.

## Settings reference

| Setting | Key | Environment variable | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Mode** | `mode` | — | `"enforcing"` | `"enforcing"` or `"audit"` (see [Operating modes](#operating-modes)) |
| **API key** | `api_key` / `typesafe_api_key` | `TYPESAFE_API_KEY` | `""` | TypeSafe AI API key |
| **Base URL** | `base_url` | — | TypeSafe API default | HTTPS endpoint, or loopback HTTP endpoint |
| **Model** | `model` | — | `"jev-latest"` | System One evaluation model |
| **Timeout** | `timeout_ms` | — | `1500` | Evaluation HTTP timeout in milliseconds |
| **Fast path** | `fastpath_enabled` | — | `true` | Enable the local sub-millisecond filter |
| **Context awareness** | `context_awareness_enabled` | — | `true` | Enable session intent caching and intent-aware evaluation |
| **Intent TTL** | `intent_ttl_minutes` | — | `30` | Backstop lifetime of a stored prompt intent in minutes (1–1440); the Claude `Stop` hook normally ends it sooner. User config only |
| **Audit log** | `audit_log_path` | — | `""` | Destination path for JSONL audit logging. Relative paths are anchored to `~/.jevguard` |
| **Sensitive files** | `sensitive_files` | — | *(built-in defaults)* | User config adds patterns; a trusted project config can only add more |
| **Trusted commands** | `trusted_commands` | — | *(built-in defaults)* | User-owned command prefixes allowed without a network call; merged with the built-in defaults, same as sensitive files |

**Invalid values.** If the user config is not valid JSON, it is ignored entirely and the enforcing built-in defaults apply. An invalid `mode` or `base_url` is ignored and also forces `mode` to `enforcing` as a safe fallback. An out-of-range `intent_ttl_minutes` (must be 1–1440) is ignored and the default `30` is used. Problems are printed to stderr as `jev-guard: ...` diagnostics and reported by `jev-guard doctor`.

## Operating modes

- **`enforcing`** (default) actively gates tool calls.
  - Catastrophic operations or security violations are blocked (`DENY` / exit code 2).
  - Sensitive file access, boundary escapes, and moderate-risk operations are escalated:
    - **Antigravity**: emits `"force_ask"` with `permissionOverrides`, which guarantees an approval prompt even in Turbo mode.
    - **Claude Code and Codex**: exit with **code 2** (blocked, reason on stderr), so bypass flags (`--dangerously-skip-permissions`, `--yolo`, headless `-p`) cannot run unconfirmed actions.
  - Safe, contained operations are allowed (`ALLOW` / exit code 0).
- **`audit`** is a dry run for trying `jev-guard` without interrupting your agents.
  - Every call goes through the fast path and TypeSafe AI as usual. Results are written to the audit log only if `audit_log_path` is set.
  - Every `DENY`, `ASK`, and `force_ask` is converted to `ALLOW`. Rewritten entries carry an `[AUDIT-MODE: <decision>]` prefix in their reason.

Set `mode` to `audit` only when you intend blocking results to become `ALLOW`.

## Precedence

1. **User config** (`~/.jevguard/.jevguard.json`) owns policy and endpoint settings.
2. **Credential environment variable** (`TYPESAFE_API_KEY`) supplies the API key and, when set, overrides `api_key` in the user config.
3. **Trusted project config** can add `sensitive_files`, only when its canonical path and exact SHA-256 digest match the user trust registry.
4. **Built-in defaults** include `mode: "enforcing"`, `timeout_ms: 1500`, `fastpath_enabled: true`, `context_awareness_enabled: true`, `intent_ttl_minutes: 30`, standard sensitive file patterns, and read commands.

## Project configs and trust

Repository files named `.jevguard.json` or `jevguard.json` are ignored until you explicitly trust their exact contents. Even then, only additive `sensitive_files` entries are applied. Project values for `mode`, `base_url`, API keys, `fastpath_enabled`, `context_awareness_enabled`, and `trusted_commands` are ignored. See [`.jevguard.json.example`](../.jevguard.json.example).

**Discovery.** Discovery checks the tool call's working directory and walks up to the nearest declared workspace root, inclusive. It also checks declared workspace roots directly. If no workspace root contains the working directory, discovery is bounded by the nearest `.git` directory or file; without one, it checks only the candidate directory. When a hook payload has neither a working directory nor workspace roots, the process working directory is the fallback and uses the same bounds. Target file directories are never used for config discovery.

**Trusting a file.**

```text
jev-guard config show
jev-guard config trust .jevguard.json
jev-guard config untrust .jevguard.json
```

`config trust` prints the file's canonical path, root, SHA-256 digest, supported settings, and the registry entry to review. It does not grant trust. To approve it, add that entry to `~/.jevguard/trusted-project-configs.json` yourself:

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

The digest is checked on every invocation, so editing or replacing the config requires a new reviewed record. `config untrust` identifies the registry entry to remove.

**Why the CLI does not write approvals.** A confirmation typed into an agent-controlled shell would not prove that you reviewed it. This design assumes the agent process cannot write the user config or `~/.jevguard/trusted-project-configs.json`. If an agent can run arbitrary commands with the same filesystem access as you, approval text and file ownership alone cannot enforce that boundary; protect those files with an OS or product-level permission boundary outside the agent's writable paths.

## Audit log

When `audit_log_path` is set, every tool evaluation produces a JSONL entry:

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

## Recommended `.gitignore` entries

Keep local audit logs out of your repository:

```gitignore
.jevguard.log
*.jevguard.log
```
