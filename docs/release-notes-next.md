# Next release (draft)

Changes since v0.3.0. Assign a version and confirm CI before publishing.

## Highlights

- Report the model that actually answered a semantic evaluation in `eval --json` (`typesafe_model`) and audit logs (`model`), making changes behind `jev-latest` visible. This completes the model-recording portion of #63; broader calibration and benchmarking remain separate work.
- Track untrusted Claude Code web and MCP tool results with deterministic session taint. The default `taint_mode` is `audit`, which records where enforcement would ask without changing verdicts. Set `enforce` in user configuration to hold risky actions for confirmation. Tool output is never sent to a classifier. This implements the deterministic portion of #60; optional content classification remains deferred.
- Harden user-intent authorization: require confidence, retain workspace boundaries and unconditional anti-tampering checks, and cap intent-authorized credential access at confirmation when a call can send data off the machine.
- Support Codex prompt-intent lifecycle hooks and opt-in Antigravity transcript intent, with transcript protection across agents when enabled.

## Fixes

- Use one network-egress heuristic for credential intent authorization and session taint (#76). Preserve URL-target and package-publish coverage while extending taint checks to the shared detector's cloud clients and inline network markers. Tainted sessions can therefore report or prompt on more network-capable calls.
- Check resolved filesystem locations before granting local path proof (#74). Aliases into execution-sensitive directories such as `.claude/`, including new files beneath an aliased directory, retain the model's containment check. Ordinary files in Claude Code worktrees remain eligible for local proof.

## Upgrade notes

- Run `jev-guard init` for each configured harness and scope to install the updated hooks. Manual hook configurations should follow [the hook examples](hooks.md).
- Existing users receive audit-only taint behavior by default. Review [tool-output taint](security-model.md#tool-output-taint) before enabling enforcement; its hook coverage is currently Claude Code only.
- Antigravity transcript intent remains off by default. Enabling it explicitly trusts agents with shell access not to forge the transcript.
- Provider-independent adapters in open PR #43 are outside this release draft.

## Remaining issue scope

- #63: model recording has landed; benchmark expansion and model comparisons remain.
- #60: deterministic taint has landed; content classification requires separate evidence and privacy decisions.
- #75 and #77: session-file cleanup and trust-path canonicalization remain deferred because they require concurrency and migration design respectively.
