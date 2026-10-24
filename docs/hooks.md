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
- `PostToolUse` marks the session as tainted after `WebFetch`, `WebSearch` or an MCP tool returns content (see [Tool-output taint](security-model.md#tool-output-taint)). It sends no tool output anywhere.

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
    ],
    "PostToolUse": [
      {
        "matcher": "WebFetch|WebSearch|mcp__.*",
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
> `jev-guard` formats Claude Code `PreToolUse` verdicts using the standard `hookSpecificOutput.permissionDecision` schema. `ALLOW` is returned as `permissionDecision: "allow"`. `ASK` and `DENY` verdicts are returned as exit code 2 with the reason on stderr (Codex behaves the same). Ingest confirmations go to stderr so they never pollute your prompt. A `PostToolUse` payload is recognized by its `hook_event_name` and is never gated as a pending call. It always exits 0. With `taint_mode: "enforce"` it also returns `hookSpecificOutput.additionalContext` that tells the model to treat the output as data.

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

`init` does not install a `PostToolUse` hook for Codex, so tool-output taint does not cover Codex. Codex's hosted web search also bypasses hooks.

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

Antigravity's documented `PreInvocation` payload includes a transcript path but not the prompt text, and the transcript JSONL format is undocumented. `jev-guard init --agent antigravity` therefore installs stateless tool gates and removes any older managed `PreInvocation` ingest hook. Prompt-bearing payloads remain supported through the explicit `jev-guard ingest` command. Antigravity post-tool hooks are unverified, so tool-output taint does not cover Antigravity.
