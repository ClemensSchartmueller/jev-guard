# Manual hook setup

`jev-guard init` writes these hooks for you, and is the recommended route. Use this page if you manage hook files by hand or want to see what `init` generates. The examples call `jev-guard` from `PATH`; `init` uses the binary's absolute path instead.

`init` writes to these files:

- Project scope: `.claude/settings.json`, `.codex/hooks.json`, `.agents/hooks.json`.
- User scope (`--scope user`): `~/.claude/settings.json`, `~/.codex/hooks.json`, `~/.gemini/config/hooks.json`.

Contents:

- [Claude Code](#claude-code-claudesettingsjson)
- [Codex CLI](#codex-cli-codexhooksjson)
- [Antigravity](#antigravity-agentshooksjson)

The default `PreToolUse` matchers cover the tools listed in the examples below. To gate selected MCP calls, add their exact `mcp__server__tool` names to the jev-guard `PreToolUse` matcher for your harness. The gate treats those calls as potential network egress, including calls to local servers. See [Egress policy](security-model.md#threat-injected-instructions-in-the-prompt).

Managed `PreToolUse` hooks have a harness timeout of at least 20 seconds. The gate gives itself 10 seconds and caps each hook payload at 8 MiB. Deadline, input, and recoverable evaluation failures return the harness's hold response.

- Claude Code blocks `PreToolUse` on exit code 2. With the installed `onFailure: "block"` setting, Claude Code 2.1.295 and later also blocks when a command hook fails to start, crashes, or times out. [Claude Code hooks reference](https://code.claude.com/docs/en/hooks#exit-code-output)
- Codex blocks `PreToolUse` on exit code 2. Its documented default timeout for most command hooks is 600 seconds. The documentation does not specify a blocking guarantee for a crashed or timed-out `PreToolUse` process. [Codex hooks reference](https://developers.openai.com/codex/hooks)
- Antigravity uses a JSON decision on stdout. Its native hook reference describes a 30-second default timeout. Its plugin hook documentation says it treats nonzero exits as hook errors and ignores them. The native reference does not specify a blocking guarantee for a crashed or timed-out process. [Antigravity hooks reference](https://antigravity.google/docs/hooks#hook-handler-configuration) · [Antigravity plugin development](https://antigravity.google/docs/build-plugins#lifecycle-hooks)

Run `jev-guard init` again to update existing managed hook commands and timeouts. In Codex, approve the updated hook in `/hooks`.

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
            "command": "jev-guard",
            "timeout": 20,
            "onFailure": "block"
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

The hooks do the same jobs as in Claude Code:

- `UserPromptSubmit` stores your prompt as session intent, scoped to the event's `turn_id`.
- `Stop` clears that intent when the turn finishes.
- `PreToolUse` gates each tool call, and uses the intent only if its `turn_id` matches.

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
        "matcher": "Bash|exec_command|apply_patch|view_file|read_file|list_dir",
        "hooks": [
          {
            "type": "command",
            "command": "jev-guard",
            "timeout": 20
          }
        ]
      }
    ]
  }
}
```

Codex intent does not depend on `antigravity_transcript_intent`. Codex loads project hooks only when the project is trusted. Run `/hooks` in the Codex CLI to review and trust the hooks before they can run. Any hook that is new or edited needs a new review, including the `UserPromptSubmit` and `Stop` hooks that `init` adds to an existing setup. Until then the gate still works, but without prompt intent. `jev-guard doctor` warns if these hooks are missing from the file, but it cannot tell whether Codex has trusted them.

`ingest` and `end-turn` print nothing to stdout, because Codex would inject that text into the model's context. Every `ASK`, `force_ask`, and `DENY` exits with code 2 and the reason on stderr, because `jev-guard` never emits `permissionDecision: "ask"`.

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
            "command": "jev-guard --antigravity-hook",
            "timeout": 20
          }
        ]
      }
    ]
  }
}
```

If the `jev-guard` section already exists with `"enabled": false`, `init` sets it to `true`.

Antigravity only needs `PreToolUse`. Its payload has a transcript path but not the prompt text, so by default it gets no intent. `jev-guard init --agent antigravity` installs the tool gates and removes any older managed `PreInvocation` ingest hook. Do not add that hook back.

To read your latest request from the conversation transcript at each `PreToolUse`, set `antigravity_transcript_intent` to `true` in `~/.jevguard/.jevguard.json`. It needs no extra hooks. It is off by default because an agent with shell access can still forge a transcript. See [Intent per agent](security-model.md#intent-per-agent). Prompt-bearing payloads remain supported through the explicit `jev-guard ingest` command. Antigravity post-tool hooks are unverified, so tool-output taint does not cover Antigravity.
