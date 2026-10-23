# Manual hook setup

`jev-guard init` writes these hooks for you, and is the recommended route. Use this page if you manage hook files by hand or want to see what `init` generates. The examples call `jev-guard` from `PATH`; `init` uses the binary's absolute path instead.

`init` writes to these files:

- Project scope: `.claude/settings.json`, `.codex/hooks.json`, `.agents/hooks.json`.
- User scope (`--scope user`): `~/.claude/settings.json`, `~/.codex/hooks.json`, `~/.gemini/config/hooks.json`.

Contents:

- [Claude Code](#claude-code-claudesettingsjson)
- [Codex CLI](#codex-cli-codexhooksjson)
- [Antigravity](#antigravity-agentshooksjson)

## Claude Code (`.claude/settings.json`)

Add hooks to `.claude/settings.json` (project) or `~/.claude/settings.json` (global):

- `UserPromptSubmit` stores your prompt as session intent.
- `Stop` clears that intent when the reply finishes.
- `PreToolUse` gates each tool call.

Do not add `SubagentStop`: a subagent finishing must not clear the main reply's intent.

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
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "jev-guard end-turn"
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell|Read|Edit|MultiEdit|Write|NotebookEdit|Glob|Grep|WebFetch|WebSearch|View|ReadLocalFile|LS",
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
> `jev-guard` formats Claude Code `PreToolUse` verdicts using the standard `hookSpecificOutput.permissionDecision` schema. `ALLOW` is returned as `permissionDecision: "allow"`. `ASK` and `DENY` verdicts are returned as exit code 2 with the reason on stderr (Codex behaves the same). Ingest confirmations go to stderr so they never pollute your prompt.

## Codex CLI (`.codex/hooks.json`)

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

Codex loads project hooks only when the project is trusted. Run `/hooks` in the Codex CLI to review and trust the hook before it can run; editing the hook requires a new review.

## Antigravity (`.agents/hooks.json`)

```json
{
  "jev-guard": {
    "PreToolUse": [
      {
        "matcher": "run_command|write_to_file|replace_file_content|multi_replace_file_content|view_file|list_dir|grep_search|find_by_name|read_resource|read_url_content",
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

If the `jev-guard` section already exists with `"enabled": false`, `init` sets it to `true`.

Antigravity's documented `PreInvocation` payload includes a transcript path but not the prompt text, and the transcript JSONL format is undocumented. `jev-guard init --agent antigravity` therefore installs stateless tool gates and removes any older managed `PreInvocation` ingest hook. Prompt-bearing payloads remain supported through the explicit `jev-guard ingest` command.
