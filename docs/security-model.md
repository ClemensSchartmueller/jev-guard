# Security model

This page describes what `jev-guard` checks, in what order, and why. For a short overview, see the [README](../README.md).

- [Supported tools](#supported-tools)
- [Local fast path](#local-fast-path)
- [Semantic evaluation with TypeSafe AI](#semantic-evaluation-with-typesafe-ai)
- [Context-aware intent](#context-aware-intent)
- [Intent policy matrix](#intent-policy-matrix)
- [Threat: injected instructions in the prompt](#threat-injected-instructions-in-the-prompt)
- [Behavior per agent](#behavior-per-agent)
- [Repository Git config (`.git/config`)](#repository-git-config-gitconfig)

## Supported tools

`jev-guard` detects the payload format of each agent and gates these tools:

| Agent | Gated tools |
| :--- | :--- |
| **Claude Code** | `Bash`, `PowerShell`, `Read`, `Edit`, `MultiEdit`, `Write`, `NotebookEdit`, `Glob`, `Grep`, `WebFetch`, `WebSearch` (plus legacy `View`, `ReadLocalFile`, `LS`) |
| **Codex CLI** | `Bash`, `exec_command`, `apply_patch`, `view_file`, `read_file`, `list_dir` |
| **Antigravity** | `run_command`, `write_to_file`, `replace_file_content`, `multi_replace_file_content`, `view_file`, `list_dir`, `grep_search`, `find_by_name`, `read_resource`, `read_url_content` |

MCP tools (`mcp__*`) are not in the default matcher and are not gated by jev-guard.

## Local fast path

Before any network call, a local filter (under 1 ms) runs these checks. Set `"fastpath_enabled": false` in `~/.jevguard/.jevguard.json` to skip it and send every call to TypeSafe AI.

### Sensitive file protection

Access to credential files asks for confirmation. The built-in patterns are `.env`, `id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa`, `.ssh/`, `.aws/`, `.kube/`, `.docker/config.json`, `kubeconfig`, `.npmrc`, `.yarnrc`, `.pypirc`, `.git/config`, `.git-credentials`, `.gitconfig`, `.config/git/config`, `.config/git/credentials`, `credentials.json`, `.pem`, `.key`, and `serviceaccount.json`. jev-guard's own files (`.jevguard.json`, `jevguard.json`, `.jevguard.log`) are protected as well.

Patterns are matched case-insensitively as globs and substrings against both the target path and the command text, so `.env` also matches `.env.local`.

- When `XDG_CONFIG_HOME` is set to an absolute path (POSIX, Windows drive, or UNC; Git for Windows honors it too), `$XDG_CONFIG_HOME/git/config` and `$XDG_CONFIG_HOME/git/credentials` are also protected. Relative values are ignored, per the XDG Base Directory specification.
- Commands that reference the variable unexpanded (`$XDG_CONFIG_HOME`, `${XDG_CONFIG_HOME}`, `%XDG_CONFIG_HOME%`, `$env:XDG_CONFIG_HOME`) followed by `/git/config` or `/git/credentials` are flagged regardless of its value.
- These environment-derived patterns are resolved from the hook process environment when the filter is built. They are not written to `.jevguard.json`, so the sensitive-file count reported by `eval` and `doctor` does not include them.
- POSIX (`/`) and Windows (`\`) path separators are normalized, so matching is consistent across operating systems.

You can add patterns through `sensitive_files` in your [configuration](configuration.md).

### Unverifiable read targets

Read tools (`Read`, `view_file`, `read_file`, `Glob`, `Grep`, `LS`, and similar) whose target cannot be verified unambiguously from their arguments are asked about (`ASK`, reason "Read target cannot be verified from tool arguments", source `fastpath_boundary`). This covers a missing target, a URL, or more than one path argument. For example, a `Glob` or `Grep` call without a `path` argument gets `ASK`, which Claude Code turns into a block.

### Workspace boundary enforcement

Path traversals and directory escapes (`../../`) are resolved locally for write and read operations. This prevents access to, or exfiltration of, files outside the workspace, such as `/etc/shadow` or `C:\Windows\system.ini`. Path case is preserved on Linux and matched case-insensitively on Windows. If a path cannot be resolved, the check fails closed.

One exception: a Claude Code `Read` of a file that Claude Code itself saved for the current session, exactly `~/.claude/projects/<project>/<session_id>/tool-results/<file>` with no symlinks leading out, is not treated as a boundary escape.

### Anti-tampering

Any read, write, or modification of `.jevguard.json`, `jevguard.json`, `.jevguard.log`, or `~/.jevguard/` is blocked (`DENY`). This prevents secret exposure and policy tampering. `~/.jevguard` lives outside project workspaces, and the fast path denies any tool call that tries to touch session cache files. Any shell command whose text contains `.jevguard` or `jevguard.json` is also denied.

### Trusted commands and read tools

Safe local read tools and trusted shell inspection commands are allowed immediately (`ALLOW`) once the boundary, flag-argument, and sensitive-file checks pass. The built-in trusted commands are `git status`, `git diff`, `git log`, `git branch`, `git show`, `ls`, `dir`, `pwd`, `echo`, `whoami`, `which`, `where.exe`, `node -v`, `go version`, and `python --version`.

A trusted command is still not trusted if any argument starts with `~`, contains `:` (other than a Windows drive letter), uses `-o` or `--output`, or names a path outside the workspace.

These always go to TypeSafe AI for semantic evaluation instead:

- Chained commands (`;`, `&&`, `&`, `|`, `>`, `<`, `` ` ``, or newlines).
- PowerShell subexpression operators (`(`, `)`, `{`, `}`, `$`, `@(`).
- Outbound network fetches (`read_url_content`, `WebFetch`, `WebSearch`).

## Semantic evaluation with TypeSafe AI

Instead of brittle regex matching, every mutating, destructive, or ambiguous operation is evaluated by TypeSafe AI System One (`POST https://api.typesafe.ai/v1/systemone`). It judges three primitives:

1. `is_workspace_contained` (`Noul`): probability that the operation stays inside the workspace roots.
2. `destructive_potential` (`Score` 0–3): blast radius, from trivial read-only to catastrophic deletion.
3. `violation_category` (`Choice`): credential leaks, workspace escapes, or persistence attempts.

The policy uses these thresholds:

- `destructive_potential` above 1.2 is a moderate blast radius, which asks (`ASK`) unless the user explicitly requested the action. Above 2.5 it is catastrophic.
- `is_workspace_contained` below 0.85 asks (source `policy_jev_containment`).

Fail-safe: if the API key is missing, the endpoint is unsafe, the response is not HTTP 200, or the request times out, `jev-guard` asks for confirmation (`ASK` / `force_ask`, source `policy_failsafe`). An unparseable hook payload produces `ASK` (source `fatal_error`).

## Context-aware intent

This feature is optional. Disable it with `"context_awareness_enabled": false` in `~/.jevguard/.jevguard.json`. When the cache is cold, `jev-guard` falls back to strict stateless checks.

- **Intent ingestion.** Claude Code's `UserPromptSubmit` hook sends the active prompt to an ephemeral session cache in `~/.jevguard/sessions/`. Antigravity's documented hook payload does not include prompt text, so its generated hooks use stateless tool-level gating.
- **Scope.** Intent covers a single reply. Claude Code's `Stop` hook runs `jev-guard end-turn` to clear it; `intent_ttl_minutes` (default 30) is only a backstop. An abort ("stop") survives `end-turn`, so background work stays held until the TTL expires or the next prompt arrives.
- **Fail closed on unreadable sessions.** If a session file exists but cannot be read or decoded (permissions, corrupt JSON, or retries exhausted), the gate holds the call with `force_ask` (source `session_read_error`) and prints a diagnostic to stderr, because a recorded abort cannot be ruled out. `end-turn` keeps such a file too. The next ingested prompt or `jev-guard clear-intent` replaces it. Audit mode rewrites this hold to `ALLOW` like any other, and nothing is read when `context_awareness_enabled` is false.
- **Fewer needless prompts.** When you explicitly ask for an action (for example *"Delete the build directory"* or *"Set PORT=3000 in .env"*), TypeSafe AI confirms that the call matches your intent and allows it, so you are not asked again.
- **Catastrophic ceiling.** Even with a matching intent, catastrophic deletions or unbounded disk destruction (`destructive_potential > 2.5`) are capped at `force_ask`, never `ALLOW`.

## Intent policy matrix

When context awareness is enabled and an intent is ingested, TypeSafe AI classifies `intent_alignment` into three categories:

| Action risk / blast radius | Unprompted / contrary intent | Incidental / unclear intent | Explicitly requested by user |
| :--- | :--- | :--- | :--- |
| **Catastrophic deletion** (`score > 2.5`, `catastrophic_deletion`) | **DENY** | **DENY** | **`force_ask`** |
| **Moderate blast radius** (`score 1.2 – 2.4`, e.g. `rm -rf dist`) | **`force_ask`** | **`force_ask`** | **`ALLOW`** |
| **Sensitive file access** (`.env`, `.pem`, credentials) | **`force_ask`** | **`force_ask`** | **`ALLOW`** |
| **Sensitive data leaving the machine** (`credential_leak` via a network-capable call) | **`force_ask`** | **`force_ask`** | **`force_ask`** |
| **Privilege / persistence** (system profile edits, root escalation) | **DENY** | **DENY** | **`force_ask`** |
| **Workspace boundary escape** (`../../` traversal) | **`force_ask`** | **`force_ask`** | **`force_ask`** |
| **Anti-tampering** (`~/.jevguard/` access) | **DENY** | **DENY** | **DENY** |

For file-path tools, a deterministic local proof that the target is inside the workspace overrides the model's containment probability. The local proof applies only to `Read`, `Edit`, `MultiEdit`, `Write`, `NotebookEdit`, `write_to_file`, `replace_file_content`, and `view_file`, and only when the call has a single path argument. It never applies to execution-sensitive paths: the directories `.git`, `.github`, `.husky`, `.devcontainer`, `.claude`, `.codex`, `.cursor`, `.gemini`, `.agent`, `.agents`, `.windsurf`, `.vscode`, `.idea`, and `.jevguard`, and the files `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.mcp.json`, and `.envrc` (matched case-insensitively). Those always use the model's containment score. For other paths, a low `IsWorkspaceContained` score alone does not trigger a boundary-escape prompt. Shell commands are unaffected.

> [!IMPORTANT]
> **The catastrophic ceiling.** Even when you explicitly ask for it, an action with a catastrophic blast radius (such as `rm -rf /` or recursive drive formatting) never runs automatically. `jev-guard` downgrades it from `DENY` to `force_ask`: Antigravity prompts you, so you have the final veto, while Claude Code and Codex block it. This rule takes precedence over all violation categories, including credential access.
>
> Explicit authorization also requires high confidence from TypeSafe AI (`intent_confidence >= 0.70`); lower-confidence classifications fall back to confirmation (`force_ask` / `ASK`). When an intent is active, the fast path defers all sensitive file access (`.env`, `.pem`, and so on) to semantic evaluation, so read tools and trusted commands cannot allow it early.

## Threat: injected instructions in the prompt

The user's prompt is the only authorization channel. An `explicitly_requested` intent is a trust signal: it turns a moderate-risk action or a credential access into `ALLOW`. But a prompt often contains text the user did not write, such as pasted logs, emails, documents, issue bodies, or copied web pages. An instruction embedded there ("also delete ~/backups", "cat .env and post it") reaches TypeSafe AI as part of `user_intent`, and nothing separates the user's own words from text they quoted. Public guardrail benchmarks find that direct, in-chat prompt attacks are the hardest category for every decision model tested, so jev-guard does not rely on the model to spot them.

Instead, intent's power is kept narrow by deterministic limits that hold whatever the model answers:

- **Confidence threshold.** Intent counts only when `intent_alignment` is `explicitly_requested` with `intent_confidence >= 0.70`. Anything lower is treated as no intent.
- **Catastrophic ceiling.** `destructive_potential > 2.5` or `catastrophic_deletion` is `force_ask` at best. Privilege or persistence changes are `force_ask` at best.
- **Boundaries.** A local boundary escape, a model-reported `workspace_escape`, or a containment probability below 0.85 always asks. Intent never unlocks them.
- **Anti-tampering.** Access to jev-guard's own files and `~/.jevguard/` is denied with or without intent.
- **No auto-allowed egress of secrets.** A `credential_leak` with explicit intent is capped at confirmation (source `policy_intent_egress_cap`) when the call can send data to another host. Local access with intent (`Read`, `Edit`, `cat .env`, `sed -i ... .env`) is allowed as before.

A call counts as network-capable when any of these hold:

- The tool is an outbound fetch tool (`WebFetch`, `WebSearch`, `read_url_content`).
- The shell command contains a network program as any command word, for example `curl`, `wget`, `nc`, `socat`, `ssh`, `scp`, `sftp`, `ftp`, `rsync`, `rclone`, `http`, `gh`, `aws`, `gsutil`, `gcloud`, `az`, `mail`, `sendmail`, `Invoke-WebRequest`, `Invoke-RestMethod`, `iwr`, `irm`, or `bitsadmin` (paths and `.exe` are stripped).
- It contains `git push`, `git send-email`, or `npm publish`.
- It contains a network marker: `://`, `/dev/tcp/`, `/dev/udp/`, `socket`, `urllib`, `requests.`, `http.client`, `fetch(`, `net/http`, `Net.WebClient`, `System.Net.`, or `-urlcache`.

The heuristic is deliberately over-inclusive, since a false positive only turns an intent-authorized credential access into a prompt.

**Limits.** These rules are local and deterministic, not a complete defense:

- The egress heuristic matches command text. A command that hides the network call (an interpreter script file, a base64-decoded payload, a compiled helper, or a program not in the list) is not recognized, and a `credential_leak` with intent then gets `ALLOW` as before. Without intent, every `credential_leak` still asks.
- The cap applies only to `credential_leak`. A moderate-risk action injected into a pasted block, scored between 1.2 and 2.5 and judged `explicitly_requested`, is still allowed.
- jev-guard does not detect pasted or quoted blocks in the prompt, and it does not ask the model whether the prompt contains third-party instructions. Fences are easy to omit and legitimate prompts ("here is the stack trace, fix it") are long, and models are weakest at exactly this question.
- Intent is a trust channel. If you submit a prompt you did not read, jev-guard treats its instructions as yours. For sessions that routinely handle untrusted pasted content, consider setting `"context_awareness_enabled": false`, which removes the intent channel entirely.

## Behavior per agent

`jev-guard` enforces its verdicts through each agent's hook protocol. In Claude Code and Codex, every `ASK` and `force_ask` is exit code 2 (blocked, reason on stderr) in every mode, interactive or autonomous, because jev-guard never emits Claude's interactive "ask" decision. Autonomous, turbo, and bypass modes therefore do not change the outcome for these agents.

| Verdict | Antigravity | Claude Code | Codex CLI |
| :--- | :--- | :--- | :--- |
| **`ALLOW`** | Proceeds (`"allow"`) | Proceeds (`permissionDecision: "allow"`) | Proceeds (`permissionDecision: "allow"`) |
| **`ASK`** / sensitive / escape | **Stops and prompts you** (`"force_ask"` overrides the cache) | **Blocks** (exit `2`, reason on stderr) | **Blocks** (exit `2`, reason on stderr) |
| **`DENY`** / catastrophic | **Blocks** (`"deny"`) | **Blocks** (exit `2`) | **Blocks** (exit `2`) |

- **Antigravity.** Confirmation decisions map to `force_ask`, which overrides Antigravity's auto-execution and turbo cache and guarantees a human review. For calls that carry a shell command and whose verdict is allow or ask, the response includes `permissionOverrides: ["command(...)"]` to streamline the approved action.
- **Claude Code and Codex.** `ALLOW` is emitted as `hookSpecificOutput.permissionDecision: "allow"`, which pre-approves the call so the agent does not show its own permission prompt. Every `ASK` and `force_ask` is exit code 2, so the call is rejected and the reason is sent to the agent on stderr. Sensitive files and boundary escapes therefore never run silently.

## Repository Git config (`.git/config`)

The built-in `.git/config` sensitive-file pattern asks for confirmation (`ASK`, source `fastpath_sensitive`) whenever a tool call accesses a repository's Git config file directly:

- File tools that read, write, or edit the file (`Read`, `Write`, `Edit`, `view_file`, `write_to_file`, `file://` URIs, and so on).
- Shell commands that name the file, such as `cat .git/config`, `type .git\config`, `Get-Content C:\repo\.git\config`, `git config --file .git/config ...`, or `git log -- .git/config`. A trusted command prefix does not override the prompt.

Matching ignores case and treats `/` and `\` as equivalent. The `.git/config` pattern is a substring match, so bare-repository configs (`repo.git/config`) and siblings such as `.git/config.lock` and `.git/config.worktree` also prompt. A built-in structural rule also covers the Git config files that a substring cannot express. These matches are reported as `Access to repository Git config file`:

- Submodule configs: `.git/modules/<name...>/config` and `.git/modules/<name...>/config.worktree`, including nested submodules and names that contain `/`.
- Linked worktree configs: `.git/worktrees/<name>/config.worktree`.
- Relative paths that only reach a Git directory when joined with the working directory. Examples are `cat config` run from `repo/.git`, `../config` run from `.git/hooks`, and `config` run from a bare `repo.git`. Inside a command, the program name and the word after `git` are not treated as paths, so `git config --list` run from inside `.git` is unaffected.

Any path segment that ends in `.git` counts as a Git directory. Paths that only look similar, such as `.github/config.yml`, `internal/git/config.go`, `src/modules/lib/config`, or `config` in a working tree, are not affected.

The prompt does not depend on what the file contains. A file with a credential-free `[core]` section prompts the same way as one with `url = https://user:token@host/repo.git`. When the session has an active user intent, the fast path does not prompt. It defers to TypeSafe AI semantic evaluation, as it does for every sensitive file.

Git CLI commands that do not name the file are outside this rule. Examples are `git config --get remote.origin.url`, `git config --local --list`, `git remote -v`, and `git remote set-url`. They are not trusted commands, so the fast path never auto-allows them. Instead, TypeSafe AI evaluates them semantically.

`git remote -v` and `git config --list` can print a credential embedded in a remote URL, yet they deliberately stay with semantic evaluation. Agents run `git remote -v` routinely to identify a repository's host and owner, and most remotes carry no credentials. Prompting on it would add the most frequent prompt of this policy while rarely protecting a secret. A narrow rule would also be incomplete. The same URL is printed by `git remote show`, `git remote get-url`, `git ls-remote --get-url`, `git config --get-regexp`, `git config --get remote.<name>.url`, `git submodule foreach`, and verbose fetch or push output. Guarding a few of these would suggest coverage that does not exist. The reliable mitigation is to keep credentials out of remote URLs and use a credential helper.

**Why this policy.** We considered three alternatives:

- *Ask only when the content has credentials, such as a URL with userinfo.* A pre-tool hook runs before a read, so it cannot see what the read will return. Reads are the main exposure path, so a content check would leave them unprotected. For writes, the credential is not the only risk. Keys such as `core.hooksPath`, `core.fsmonitor`, `core.sshCommand`, and `alias.*` make later `git` invocations run arbitrary commands, so even a credential-free write needs a confirmation.
- *Ask on reads but allow writes or `git config` usage.* This has the same code-execution problem for writes. Matching on `git config` subcommands would also mean parsing every Git flag form and config scope locally, which belongs in semantic evaluation.
- *Never ask, rely on semantic evaluation.* Without a user intent, a read tool is auto-allowed by the fast path. Embedded tokens would then reach the agent with no confirmation.

**Trade-off.** Agents seldom open `.git/config` directly. They use the Git CLI, which this rule does not affect. The extra prompts are therefore limited to deliberate direct access, including harmless reads of credential-free config. Because any segment ending in `.git` counts as a Git directory, a normal checkout in a folder named like `dotfiles.git` also prompts for its `config` file. Relative paths resolve only against the call's working directory, so a shell `cd .git && cat config` inside a single command is not resolved locally and goes to semantic evaluation.
