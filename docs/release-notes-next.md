# v0.4.0 — Intent and Tool-Output Hardening

Changes since v0.3.0.

## Highlights

- Report the model that actually answered a semantic evaluation in `eval --json` (`typesafe_model`) and audit logs (`model`), making changes behind `jev-latest` visible. This completes the model-recording portion of #63; broader calibration and benchmarking remain separate work.
- Track untrusted Claude Code web and MCP tool results with deterministic session taint. The default `taint_mode` is `audit`, which records where enforcement would ask without changing verdicts. Set `enforce` in user configuration to hold risky actions for confirmation. Tool output is never sent to a classifier. This implements the deterministic portion of #60; optional content classification remains deferred.
- Harden user-intent authorization: require confidence, retain workspace boundaries and unconditional anti-tampering checks, and cap intent-authorized credential access at confirmation when a call can send data off the machine.
- Support Codex prompt-intent lifecycle hooks and opt-in Antigravity transcript intent, with transcript protection across agents when enabled.

## Fixes

- Close anti-tampering bypasses through shell escapes, wildcard globs, bare command words, and disabled fast-path checks. Bound shell scanning and filesystem resolution work, returning confirmation when a check cannot finish safely.
- Add an offline policy regression corpus and name the existing policy thresholds without changing their values.

- Use one network-egress heuristic for credential intent authorization and session taint (#76). Preserve URL-target and package-publish coverage while extending taint checks to the shared detector's cloud clients and inline network markers. Tainted sessions can therefore report or prompt on more network-capable calls.
- Honor project config trust approved under another spelling of the same directory, such as a symlinked checkout, macOS `/var` versus `/private/var`, a case variant, or a Windows short name (#77). `config trust` now proposes a record for the symlink-resolved directory marked `"canonical": true`. A canonical record applies to any spelling of the same real file and directory, but only while its own path is reached without any symlink or junction. This is checked with pinned, handle-based lookups on Linux, FreeBSD, macOS, and Windows, so replacing the recorded directory with a link, before or during a check, does not carry trust to another directory, even one with byte-identical config. The checked config is hashed from a file opened relative to the checked directory's handle (`openat` on Linux, FreeBSD, and macOS; `NtCreateFile` relative to the directory handle on Windows), so switching a link in the checked path cannot pair the approved directory with a hard link to its config in another directory. On Windows, recorded directories are compared with the final path Windows reports exactly, including case, because case-sensitive directories can hold names that differ only in case; `config trust` proposes that exact spelling. Other platforms cannot pin lookups, so canonical records never apply there, and `config trust` proposes exact-path records. The digest is still checked. `config untrust` lists every registry entry to remove, and `config untrust` and `doctor` name records for another spelling that do not apply. Lookups stop after a short deadline when an entry is unreachable, such as on a stale network mount: exact-path records without `canonical` are still honored, canonical records fail closed, and `config untrust` and `doctor` say the check was incomplete (#88). This includes the check, after the config is read, that the checked path still names the directory it was read from. The hook never resolves symlinks to build a proposal.
- Check resolved filesystem locations before granting local path proof (#74). Aliases into execution-sensitive directories such as `.claude/`, including new files beneath an aliased directory, retain the model's containment check. Ordinary files in Claude Code worktrees remain eligible for local proof.

## Upgrade notes

- Existing project trust records, which have no `canonical` field, keep working only for the exact path they name and are not checked for symlinks or junctions, as before. If a directory on such a path is replaced by a link to another directory with byte-identical config, the record still applies there. Run `jev-guard config trust` again and replace each record with the printed canonical record for the stronger binding and to cover other spellings of the same directory; `jev-guard doctor` notes configs trusted only through older records. Earlier versions ignore the `canonical` field and treat a canonical record as an exact-path record.

- Run `jev-guard init` for each configured harness and scope to install the updated hooks. Manual hook configurations should follow [the hook examples](hooks.md).
- Existing users receive audit-only taint behavior by default. Review [tool-output taint](security-model.md#tool-output-taint) before enabling enforcement; its hook coverage is currently Claude Code only.
- Antigravity transcript intent remains off by default. Enabling it explicitly trusts agents with shell access not to forge the transcript.
- Provider-independent adapters in open PR #43 are outside this release.

## Remaining issue scope

- #63: model recording has landed; benchmark expansion and model comparisons remain.
- #60: deterministic taint has landed; content classification requires separate evidence and privacy decisions.
- #75: session-file cleanup remains deferred because it requires concurrency design.
