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

The generated file contains `mode`, `timeout_ms`, `fastpath_enabled`, `context_awareness_enabled`, `intent_ttl_minutes`, `antigravity_transcript_intent`, and the full built-in `sensitive_files` and `trusted_commands` lists. Entries in `sensitive_files` and `trusted_commands` are always merged with the built-in defaults, so defaults cannot be removed.

The same directory holds the binary, trust registry, and session data:

```text
~/
└── .jevguard/
    ├── .jevguard.json                    # User-owned security settings
    ├── bin/
    │   └── jev-guard (or jev-guard.exe)  # Executable binary (install.ps1 adds this to User PATH)
    ├── sessions/
    │   ├── <session_hash>.json           # Ephemeral, atomic session intent cache
    │   ├── <session_hash>.json.lock      # Per-session write lock
    │   ├── <session_hash>.json.taint.*   # Taint and abort markers (see security model)
    │   ├── <session_hash>.json.abort.*
    │   └── .sweep                        # Cleanup sweep coordination: last run time and resume position
    └── trusted-project-configs.json      # Approved project config digests, if configured
```

`end-turn` and `status` run a cleanup sweep at most once an hour. It removes files left by abandoned sessions: markers and session files older than 48 hours, and lock files idle for 7 days whose session has no file or markers left. It never waits for a lock held by an active session and never fails a hook. Each run is bounded (it reads at most 16384 directory names and inspects at most 1024 entries, makes at most 1024 filesystem calls on at most 128 sessions, reads at most 16 MiB of a session file, keeping larger ones, and stops after about 150 ms, checked before each filesystem call) and resumes where the previous run stopped, starting over from the beginning when that position is out of reach, so a large backlog is cleared over several runs. Only one sweep runs at a time; `.sweep` is never deleted.

Run `jev-guard config show` to see the effective values and where each comes from. Secrets are never printed.

The TypeSafe client connects directly: proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY`) are ignored, and no proxy setting is supported. TLS requires version 1.2 or later. On Linux, Android and BSD, trust roots come from fixed system certificate bundle and directory paths (the Go platform defaults), ignoring `SSL_CERT_FILE` and `SSL_CERT_DIR`. On macOS, iOS and Windows, the native platform verifier supplies trust roots. Corporate CAs must be installed in the system trust store; process-local CA overrides are not supported. Other platforms use an empty trust pool and fail TLS verification. Behind a mandatory proxy, evaluations fail safe to `ASK`. `doctor` checks the same direct network path. HTTP/2 is disabled so `GODEBUG=http2debug` cannot log API credentials.

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
  "antigravity_transcript_intent": false,
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
| **Taint mode** | `taint_mode` | — | `audit` | `off`, `audit` or `enforce`: what a session tainted by `WebFetch`, `WebSearch` or MCP output changes (see [Tool-output taint](security-model.md#tool-output-taint)). User config only; an invalid value uses `enforce` |
| **Intent TTL** | `intent_ttl_minutes` | — | `30` | Backstop lifetime of a stored prompt intent in minutes (1–1440); the Claude Code or Codex `Stop` hook normally ends it sooner. Does not apply to Antigravity transcript intent. User config only |
| **Antigravity transcript intent** | `antigravity_transcript_intent` | — | `false` | Opt-in. Read Antigravity prompt intent from the conversation transcript at `PreToolUse`, and run the transcript guard for every agent. An agent with shell access can still forge a transcript, so turning this on trusts your agents not to. See [Intent per agent](security-model.md#intent-per-agent). Codex and Claude Code intent do not depend on it. User config only |
| **Audit log** | `audit_log_path` | — | `""` | Destination path for JSONL audit logging. Relative paths are anchored to `~/.jevguard` |
| **Sensitive files** | `sensitive_files` | — | *(built-in defaults)* | User config adds patterns; a trusted project config can only add more |
| **Trusted commands** | `trusted_commands` | — | *(built-in defaults)* | User-owned command prefixes eligible for the fast path. Built-in prefixes accept supported inspection options. User entries merge with the built-in defaults. |

**Invalid values.** If the user config is not valid JSON, it is ignored entirely and the enforcing built-in defaults apply. An invalid `mode` or `base_url` is ignored and also forces `mode` to `enforcing` as a safe fallback. An out-of-range `intent_ttl_minutes` (must be 1–1440) is ignored and the default `30` is used. An `antigravity_transcript_intent` that is not `true` or `false` means off. Problems are printed to stderr as `jev-guard: ...` diagnostics and reported by `jev-guard doctor`.

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
3. **Trusted project config** can add `sensitive_files`, only when its path and exact SHA-256 digest match a record in the user trust registry (see [Project configs and trust](#project-configs-and-trust)).
4. **Built-in defaults** include `mode: "enforcing"`, `timeout_ms: 1500`, `fastpath_enabled: true`, `context_awareness_enabled: true`, `intent_ttl_minutes: 30`, `antigravity_transcript_intent: false`, standard sensitive file patterns, and read commands.

## Project configs and trust

Repository files named `.jevguard.json` or `jevguard.json` are ignored until you explicitly trust their exact contents. Even then, only additive `sensitive_files` entries are applied. Project values for `mode`, `base_url`, API keys, `fastpath_enabled`, `context_awareness_enabled`, `taint_mode`, and `trusted_commands` are ignored. See [`.jevguard.json.example`](../.jevguard.json.example).

**Discovery.** Discovery checks the tool call's working directory and walks up to the nearest declared workspace root, inclusive. It also checks declared workspace roots directly. If no workspace root contains the working directory, discovery is bounded by the nearest `.git` directory or file; without one, it checks only the candidate directory. When a hook payload has neither a working directory nor workspace roots, the process working directory is the fallback and uses the same bounds. Target file directories are never used for config discovery.

**Trusting a file.**

```text
jev-guard config show
jev-guard config trust .jevguard.json
jev-guard config untrust .jevguard.json
```

`config trust` prints the file's path, root, SHA-256 digest, supported settings, and the registry entry to review. It does not grant trust. To approve it, add that entry to `~/.jevguard/trusted-project-configs.json` yourself:

```json
{
  "version": 1,
  "entries": [
    {
      "project_root": "/path/to/project",
      "config_path": "/path/to/project/.jevguard.json",
      "sha256": "digest-printed-by-config-trust",
      "canonical": true
    }
  ]
}
```

The digest is checked on every invocation, so editing or replacing the config requires a new reviewed record. `config untrust` identifies the registry entry to remove.

**Canonical records.** `config trust` proposes the config under its symlink-resolved directory and marks the record `"canonical": true`. A canonical record applies to a config file only when, at the time of the check:

- its `config_path` and `project_root` are reached from the filesystem root without any symlink or Windows junction (or other reparse point), and
- the file and directory reached that way are the same file and directory (by file identity) as the config being checked, and the digest matches. The config being checked is read and hashed from a file opened relative to the checked directory's handle (see below), so its directory identity is the one the hashed bytes were actually found in, and the checked spelling must still name that directory after the read. That last check runs only when a canonical record is looked up, under the same deadline as the other lookups (see **Unreachable entries**).

This holds whether or not the checked spelling is the recorded one. So a project approved once is trusted whether it is reached through a symlinked checkout, macOS `/var` or `/private/var`, a case variant, or a Windows 8.3 short name such as `RUNNER~1`. If a directory on the recorded path is later replaced by a symlink or junction, even one pointing at byte-identical config, the record stops applying everywhere. A hard link to the config in another directory is not trusted either. Renaming a real directory into the recorded path is not detected: the record names a location, and whatever real directory is at that location with the approved digest is trusted.

`config trust` checks its proposal the same way before printing it. If it cannot, it prints a record without `canonical` for the exact path given, and says why. This happens on platforms without pinned lookups (see below), when the real directory cannot be resolved or opened, for example on a Windows `subst` or mapped drive, or when the check does not finish in time.

**Pinned lookups.** The checks open each path step by step and compare identities read from the open handles, so a path swapped for a link between two steps cannot redirect a check. The checked spelling may go through links, so its directory is opened following them; what matters is that the config file whose bytes are hashed is bound to that directory handle:

- **Linux and FreeBSD** open the recorded path one component at a time from `/`, each relative to the handle of its parent with `O_NOFOLLOW`, then open the config file relative to the final directory handle. The checked config is read from a file opened relative to the checked directory's handle (`openat`, `O_NOFOLLOW`).
- **macOS** opens the recorded directory with `O_NOFOLLOW_ANY`, which fails if any component of the path is a symlink, and opens the config file relative to that directory handle with `openat` and `O_NOFOLLOW`. The checked config is likewise read from a file opened relative to the checked directory's handle. Go 1.23 does not export `openat` on macOS; jev-guard uses the standard library's own `openat` wrapper, which the `syscall` package exposes for linking, without cgo or extra modules. Directories are opened for reading because macOS has no `O_PATH`, so a directory on either path without read permission makes canonical records fail closed.
- **Windows** opens the recorded directory with `FILE_FLAG_OPEN_REPARSE_POINT`, rejects reparse points, and requires the final path that Windows reports for the open handle to equal the recorded `project_root` exactly, including case. A junction, symlink, `subst` drive, mapped drive, or 8.3 short name in a canonical record therefore never matches. Case is not ignored because directories can be case-sensitive (per directory, as used by WSL), where names that differ only in case are different directories; `config trust` proposes the directory exactly as Windows reports its final path, so the records it prints match. The config file is then opened relative to the held directory handle (`NtCreateFile` with a root directory handle, loaded from `ntdll.dll` without cgo or extra modules) with `FILE_OPEN_REPARSE_POINT`, and reparse points are rejected. The checked config is likewise read from a file opened relative to the checked directory's handle. Handles are held without delete sharing, so they cannot be renamed while held.
- **Other platforms** cannot pin lookups. Canonical records never apply there, and `config trust` proposes records without `canonical`.

**Records without `canonical`.** Records written by earlier versions, and records that `config trust` proposes when it cannot verify a canonical one, apply only to the exact path they name, with no filesystem checks. This keeps existing approvals working instantly, but it is a compatibility exception with a weaker binding: such a record is bound to a path string, not to a directory. If a directory on that path is renamed away and replaced by a symlink or junction to another directory with byte-identical config, the record still applies there, as it did in earlier versions. Run `config trust` again and replace such records with the canonical record it prints; `doctor` notes when a config is trusted only through a record without `canonical`. A record without `canonical` never extends to other spellings, even if its path contains no link.

A registry with canonical records stays readable by earlier versions, which ignore the `canonical` field and honor the record for its exact path only.

**Revoking.** `config untrust` lists every registry entry that applies to the config file under any spelling and digest, marking canonical ones; remove all of them to revoke trust. `config untrust` and `doctor` also name entries for another spelling of the same file that do not apply to the current one, and why.

**Unreachable entries.** Canonical records and the check for other spellings open the paths in registry entries, and canonical records also check the checked spelling again after the config was read. If an entry or the checked spelling is unreachable, for example on a stale network mount, the lookup gives up after a short deadline. Records without `canonical` that name the checked path exactly are still honored, but canonical records are treated as not applying, so the config stays untrusted rather than blocking the hook. `config untrust` and `doctor` say when the check was incomplete. The hook path never resolves symlinks to build a proposal; only `config trust` does, under the same deadline.

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

While a session is tainted by untrusted tool output, entries for decisions that `taint_mode` checks also carry a `taint` field, for example `"taint": "audit: enforce would ask (network egress); session tainted by WebFetch at 2026-09-18T11:59:30Z"`. In `audit` taint mode this field is the only record, so set `audit_log_path` if you want to measure the effect. See [Tool-output taint](security-model.md#tool-output-taint).

When TypeSafe answered the call, the entry also has `"model"`: the model id TypeSafe reported, for example a specific Jev version behind `jev-latest`. Comparing it across entries shows when the model behind a floating alias changed. Fast-path and fail-safe entries have no `model`.

## Recommended `.gitignore` entries

Keep local audit logs out of your repository:

```gitignore
.jevguard.log
*.jevguard.log
```
