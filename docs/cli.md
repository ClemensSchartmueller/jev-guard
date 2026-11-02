# CLI reference

Run `jev-guard --help` for the built-in summary. When run in an interactive terminal without piped input or flags, `jev-guard` shows help instead of waiting on stdin.

- [Commands at a glance](#commands-at-a-glance)
- [Setup and diagnostics](#setup-and-diagnostics)
- [Simulating decisions with `eval`](#simulating-decisions-with-eval)
- [Session intent](#session-intent)

## Commands at a glance

| Command | What it does |
| :--- | :--- |
| `jev-guard init` | Add hooks for your agents to the current project |
| `jev-guard doctor` | Check config, API key, network, audit log, and hook setup |
| `jev-guard config show` | Show effective policy and its source, without secrets |
| `jev-guard eval` / `explain` | Simulate how a tool call would be judged |
| `jev-guard status` | Show active sessions and the cache directory |
| `jev-guard ingest` | Store the user's prompt as session intent (used by hooks) |
| `jev-guard end-turn` | Clear intent when a reply ends (Claude Code `Stop` hook) |
| `jev-guard clear-intent` | Clear intent for one session, or all with `--all` |
| `jev-guard config trust` / `untrust` | Prepare or revoke a project config trust record ([details](configuration.md#project-configs-and-trust)) |
| `<payload-json> \| jev-guard` | Evaluate a hook payload; this is what the hooks run |

## Setup and diagnostics

```bash
# Add hooks for detected agents (or all, if none are detected)
jev-guard init
jev-guard init --agent claude      # claude | codex | antigravity | all
jev-guard init --scope user        # user-level hooks where supported (default: project)

# Diagnose config, API key, network, audit log, and hook setup (exit 1 on any [FAIL])
jev-guard doctor
jev-guard doctor --offline         # skip the network check

# Version and help
jev-guard --version
jev-guard --help
```

Without `--agent`, `init` prints the agents it detected. With `--scope user`, it writes `~/.claude/settings.json` (Claude Code), `~/.codex/hooks.json` (Codex), and `~/.gemini/config/hooks.json` (Antigravity). See [Manual hook setup](hooks.md) for what is written.

`init` preserves existing hook configuration, and running it again does not add duplicate hooks. The hooks call the installed binary by its absolute path, so they work without a `PATH` change.

`doctor` reports each check as `[OK]`, `[WARN]`, or `[FAIL]`. It exits 1 if any check fails. A missing API key is only a `[WARN]`, but without a key, every call the fast path cannot decide is held for confirmation. For Claude Code it also reports the `PostToolUse` taint hook and the effective `taint_mode`. A missing taint hook is a `[WARN]`.

`version`/`-v` and `help`/`-h` also work as aliases for `--version` and `--help`.

## Simulating decisions with `eval`

`jev-guard eval` runs the real gate pipeline (config, normalization, boundary, fast path, TypeSafe, policy, harness formatting) without a live agent:

```bash
jev-guard eval --cmd "git diff .env"
jev-guard eval --tool Write --target ../outside.txt --cwd /path/to/project --offline
jev-guard eval --payload payload.json --explain   # any supported harness payload ('-' reads stdin)
jev-guard eval --cmd "cat .env" --json
jev-guard eval --cmd "rm -rf build" --intent "Delete the build folder" --explain
jev-guard explain --cmd "git diff .env"           # shorthand for eval --explain
```

Example output:

```text
$ jev-guard eval --cmd "cat .env" --offline
ASK: Access to sensitive file or credential pattern: .env (source: fastpath_sensitive)
```

### Flags

- `--cmd CMD` simulates a Claude Code `Bash` call.
- `--tool NAME --target PATH` simulates any other tool in a Claude Code-shaped payload, passing the target under the tool's canonical path argument (`TargetFile` for `write_to_file`/`replace_file_content`, `AbsolutePath` for `view_file`, `notebook_path` for `NotebookEdit`, `path` for Glob/Grep/LS, otherwise `file_path`).
- `--payload FILE` uses a raw hook JSON payload of any harness. Use it to reproduce an exact Antigravity or Codex call.
- `--cwd DIR` sets the working directory (default: current directory).
- `--intent TEXT` simulates the user's prompt for intent-aware decisions, for example `--cmd "rm -rf build" --intent "Delete the build folder"`. It sets the intent exactly as the hook does, so the fast path defers intent-covered sensitive access to TypeSafe. A stop/cancel prompt (such as `--intent stop`) reproduces the hook's aborted-session hold. It is ignored when `context_awareness_enabled` is false (reported in `--explain` and `--json` as `intent_applied: false`). The session cache is never read or written, so a cached intent or abort from a live session never affects `eval`.
- `--offline` skips the TypeSafe network call. If the fast path has no verdict, the result says the call "would be sent to TypeSafe".
- `--explain` prints the user config and applied trusted project config paths, mode and rule sources, normalized tool call, boundary result, fast path result, TypeSafe judgments, final decision, harness-specific output, and the exit code the hook would return.
- `--json` emits a machine-readable result. The default output is one line: decision, reason, and source.

`jev-guard explain ...` is shorthand for `jev-guard eval --explain ...` and rejects `--json` and `--explain`.

### Flag syntax

Flags take values as `--flag value` or `--flag=value`. Boolean flags accept explicit values such as `--offline=false` and `--json=true` (`false`/`0` disables). A string flag never consumes a following `--option` as its value: `--cmd --offline` is a usage error. To pass a literal value beginning with `--`, use the `=` form, such as `--cmd=--version`. Each flag may be given only once.

### Side effects and exit codes

- `eval` never writes session state, ingests intents, or writes audit-log entries.
- Exit code `0` whenever the evaluation succeeded, regardless of the decision (the hook's exit code is reported in `--explain`/`--json`).
- Exit code `2` on usage errors or unreadable payloads, with a `jev-guard eval: usage error: ...` diagnostic on stderr and nothing on stdout.

### Boundary fields in `--json` output

| `boundary_status` | Meaning | `boundary_contained` |
| :--- | :--- | :--- |
| `contained` | The target resolved inside the workspace. | `true` |
| `escaped` | The target is outside the workspace or could not be resolved. | `false` |
| `no_target` | The call has no target path (such as a shell command); treated as contained, as in the hook. | `true` |
| `skipped` | The boundary stage did not run because a stop/cancel `--intent` held the call as an aborted session. | `null` |

Use `boundary_status` to tell a skipped check from an uncontained target. `boundary_contained` is kept for compatibility and is `null` only when the stage was skipped.

## Session intent

These commands are normally called by hooks. See [Context-aware intent](security-model.md#context-aware-intent) for how intent affects decisions.

```bash
# Store the active user prompt in the session cache (space-separated or --flag=value)
jev-guard ingest --session "my-session" --turn 1 --prompt "Delete the build folder"
jev-guard ingest --session="my-session" --turn=1 --prompt="Delete the build folder"

# Or pipe a hook event JSON payload on stdin
cat hook_payload.json | jev-guard ingest

# End the current reply for the session named in a hook payload (Claude Code Stop hook)
cat stop_payload.json | jev-guard end-turn
jev-guard end-turn --session "my-session"

# Clear intent for one session, or every session with --all
jev-guard clear-intent --session "my-session"
jev-guard clear-intent --all
jev-guard cache clear              # alias for clear-intent

# Show active sessions and the cache directory
jev-guard status                   # also: jev-guard cache status, jev-guard cache
```

- `ingest` sends its confirmation to stderr, so it never pollutes the user's prompt.
- `end-turn` clears only that session's intent, prints nothing to stdout, and always exits 0. A recorded abort ("stop") is kept until the TTL expires or the next prompt replaces it. A session file that cannot be read is also kept, since its abort state is unknown.
- `clear-intent` without `--session`, a stdin payload, or `--all` prints usage and exits 1.
- `status` lists unreadable session files together with their error, and shows when a session is tainted by untrusted tool output, with the tool name and time.
- The bare `jev-guard` command also handles Claude Code `PostToolUse` payloads, which taint the session. It never gates them.
- Aliases: `--session-id` and `--session_id` work for `--session`, and `--turn-id` and `--turn_id` work for `--turn`. The underscore command aliases `end_turn` and `clear_intent` also work.
