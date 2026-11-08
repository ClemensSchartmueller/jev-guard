# Security model

This page describes what `jev-guard` checks, in what order, and why. For a short overview, see the [README](../README.md).

- [Supported tools](#supported-tools)
- [Local fast path](#local-fast-path)
- [Semantic evaluation with TypeSafe AI](#semantic-evaluation-with-typesafe-ai)
- [Context-aware intent](#context-aware-intent)
- [Intent per agent](#intent-per-agent)
- [Intent policy matrix](#intent-policy-matrix)
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

Before any network call, a local filter (under 1 ms) runs these checks. Set `"fastpath_enabled": false` in `~/.jevguard/.jevguard.json` to skip it and send every call to TypeSafe AI. [Anti-tampering](#anti-tampering) is the exception: it always runs first, even with the fast path disabled.

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

Any read, write, or modification of `.jevguard.json`, `jevguard.json`, `.jevguard.log`, or `~/.jevguard/` is blocked (`DENY`). This prevents secret exposure and policy tampering, including tampering with the session cache files in `~/.jevguard`.

- Every path-like argument is checked, not only the one used as the call's target. A `source` argument next to `dest` is also checked.
- File-name filters (`glob`, `Includes`, `Excludes`, and the `pattern` of `Glob` and `find_by_name`) and shell command text are denied if they contain `.jevguard` or `jevguard.json`. Content search patterns, such as Grep's `pattern`, are not checked.
- The check runs before every other stage, including the aborted-session and session-read-error holds. It does not depend on `fastpath_enabled` or user intent. In `audit` mode the denial is logged and the call allowed, as with every other verdict.

### Antigravity transcript guard

This guard runs only if you turn on `antigravity_transcript_intent` (see [Intent per agent](#intent-per-agent)). With it off, which is the default, nothing here runs for any agent, so these rules have no cost and cause no denials. With it on, the guard runs for every agent, because any agent on the machine could forge the transcript, and it also runs when `fastpath_enabled` is false.

The guard denies access to the transcript (`DENY`, source `fastpath_tampering`), because an agent that could write it could forge your authorization. This covers any path into `.gemini/antigravity/brain/<id>/.system_generated/` in the target, another path argument, or a working directory. Each path is checked as written and as the filesystem resolves it, from its exact bytes, so a symlink to the transcript or to a parent directory is denied too, including when the final file does not exist yet. Other files under `brain/<id>/`, such as `task.md`, are not affected for file tools.

Commands and other arguments get these checks:

- **Text.** Any command whose text contains `antigravity/brain`, `.system_generated`, or `transcript.jsonl` is denied. This is broad on purpose, so an unrelated `cat transcript.jsonl` is denied too, and so is a commit message that spells one out.
- **Words.** Each word is read the way a shell would read it, then checked against the same text and resolved, and is denied if it leads anywhere under `.gemini/antigravity/brain`. The shell that will run the command is unknown, so the command is read under POSIX rules (backslashes, single and double quotes, adjacent segments, `$'...'`, `$"..."`), PowerShell rules (backtick), and cmd.exe rules (caret), and every reading is checked. `~`, `$HOME`, `$PWD`, and variables set in the hook's environment are expanded. On Windows, Git Bash's `/c/Users/...` spelling is also read as a drive. Words are also split at operators, `=`, `,`, and `:`, and values attached to a short flag (`-ofile`) or an `@` are checked.
- **Strings a program will run.** A quoted string is read as a command only when a recognized program will run it, up to 3 levels deep: `sh`, `bash`, and similar shells with `-c`, `cmd /c`, `powershell` and `pwsh`, `eval`, `su -c`, the `-c` or `-e` flags of `python`, `node`, `perl`, `ruby`, `php -r`, and `lua`, and `$(...)` or backticks outside single quotes. Other quoted text stays text, as does a heredoc's body for the text check. A command list such as `["bash", "-lc", "..."]` holds literal words, read the same way.
- **Other arguments.** File names in `apply_patch` headers count as paths. Any other one-line argument counts if it resolves into the transcript directory and its parent directory exists, so file content that only mentions the path is not denied.

A command run from a working directory under the brain directory is denied as well.

**Work limits.** A command or path argument too large to check gets `ASK` (source `transcript_guard_limit`, reason "could not be verified"). As with every other verdict, audit mode logs this as `[AUDIT-MODE: ask]` and allows the call. The limits apply to each recognized command and path argument, not to the total size of a call, so oversized text in nested or other arguments gets no limit verdict. They are 2 MiB per command (a string or an argument list), 1 MiB per path argument, 50,000 distinct words, 1,000,000 path components, 60,000 filesystem lookups, and 64 symlink hops per path, so a very large heredoc can hit them. A symlink loop also gets this `ASK`.

**This does not make shell commands safe, and turning the setting on trusts your agents not to forge a transcript.** `jev-guard` reads a command's text and does not run a shell. It cannot see the following, and such a command goes on to the remaining checks. Each of the first group is run by a test in a real `bash`: the command passes the guard, writes a record through a symlink to the transcript, and that record is accepted as your intent.

- A path computed when the command runs: a variable set in the command or differing from the hook's environment, a substitution's output, or a decoded string (`f=da; cat "work/${f}ta"`).
- A glob or a brace expansion that matches a symlink (`printf x >> work/d*`, `tee -a work/{d,e}ata`).
- A symlink made earlier in the same command.
- A relative path after a `cd` in the same command (`cd work && cat data`), when the directory itself does not lead under the brain directory.
- A script file, or a path built inside a program string, including programs that are not recognized (`sh work/run.sh`, `awk '... ("work/da" "ta")'`).
- A hard link to the transcript, which looks like an ordinary file.

These are also not modeled, and have not been run:

- A multi-line path in an argument other than the known path arguments.
- PowerShell control escapes such as `` `n ``, which are read as the plain letter, a word that holds both an apostrophe and cmd.exe quoting, and other shells' own quoting rules, such as `fish`.
- Windows name rewriting: trailing dots and spaces, 8.3 short names, and `::$DATA` streams. These depend on the file system.
- Git Bash mount paths other than a drive, such as `/tmp`.

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

- **Intent ingestion.** Claude Code's and Codex CLI's `UserPromptSubmit` hooks send the active prompt to an ephemeral session cache in `~/.jevguard/sessions/`. Antigravity's hook payload has no prompt text, so it gets no intent by default. If you opt in, `jev-guard` reads the latest explicit user request from the conversation transcript at each `PreToolUse` instead. See [Intent per agent](#intent-per-agent).
- **Scope.** Intent covers a single reply. In Claude Code and Codex, the `Stop` hook runs `jev-guard end-turn` to clear it; `intent_ttl_minutes` (default 30) is only a backstop. An abort ("stop") survives `end-turn`, so background work stays held until the TTL expires or the next prompt arrives. A session abort holds the call whichever turn it was recorded in.
- **Fail closed on unreadable sessions.** If a session file exists but cannot be read or decoded (permissions, corrupt JSON, or retries exhausted), the gate holds the call with `force_ask` (source `session_read_error`) and prints a diagnostic to stderr, because a recorded abort cannot be ruled out. `end-turn` keeps such a file too. The next ingested prompt or `jev-guard clear-intent` replaces it. Audit mode rewrites this hold to `ALLOW` like any other, and nothing is read when `context_awareness_enabled` is false.
- **Fewer needless prompts.** When you explicitly ask for an action (for example *"Delete the build directory"* or *"Set PORT=3000 in .env"*), TypeSafe AI confirms that the call matches your intent and allows it, so you are not asked again.
- **Catastrophic ceiling.** Even with a matching intent, catastrophic deletions or unbounded disk destruction (`destructive_potential > 2.5`) are capped at `force_ask`, never `ALLOW`.

### Intent per agent

| | Claude Code | Codex CLI | Antigravity |
| :--- | :--- | :--- | :--- |
| **Intent source** | `UserPromptSubmit` hook | `UserPromptSubmit` hook | None by default; opt in to read the conversation transcript at `PreToolUse` |
| **Turn scoping** | Numeric turn when the payload has one; `Stop` clears the session | Exact match on the string `turn_id`; `Stop` clears the session | The latest user message in that conversation; no `Stop` hook and no TTL |
| **Stop/abort prompt** | Holds until the TTL expires or the next prompt | Holds until the TTL expires or the next prompt | Holds while it is the latest user message |
| **Setting** | `context_awareness_enabled` turns it off | `context_awareness_enabled` turns it off | `antigravity_transcript_intent: true` turns it on; off by default. It also needs `context_awareness_enabled` |

**Codex.** `ingest` stores the `turn_id` of the `UserPromptSubmit` event, and `PreToolUse` uses that intent only when its own `turn_id` is the same, so the intent of an interrupted or older turn is never applied. If either the stored session or the call has a string `turn_id`, both must have the same one, or the call gets no intent. A `turn_id` that names no turn, such as an empty string or a JSON object, never gives intent on either side; `null` counts as no `turn_id`. A call without one therefore cannot pick up a keyed session's prompt, whichever agent sent it. A recorded abort still holds across any such mismatch. A payload with a string `turn_id` is reported as harness `codex`; other Codex payloads are reported as `claude-code`.

**Antigravity is opt-in.** With `antigravity_transcript_intent` off, which is the default, no transcript is read and Antigravity calls are gated without intent. Claude Code and Codex intent do not depend on this setting.

Setting it to `true` in `~/.jevguard/.jevguard.json` unlocks intent-based decisions for Antigravity: fewer prompts when you asked for the action, and a stop in your latest message holds the call. It also turns on the [transcript guard](#antigravity-transcript-guard) for every agent. **An agent with shell access can still forge a transcript through the guard's documented limits, and a forged record counts as your own request, so turning this on trusts your agents not to do that.** Only your user config can set it. A project config cannot, even a trusted one, and an invalid value means off, with a diagnostic. `jev-guard doctor`, `status`, `config show`, and `eval --explain` report it.

The transcript is `~/.gemini/antigravity/brain/<conversationId>/.system_generated/logs/transcript.jsonl`, and the intent is its last `USER_INPUT` / `USER_EXPLICIT` record. The payload's `transcriptPath` is used only if it resolves to exactly that location for the payload's conversation ID and is a regular file. At most the last 8 MB are scanned, and text over 8 KB is unusable.

This format is undocumented and can change, so the feature fails closed:

- If the latest user record is unusable (empty, not text, malformed, truncated, or over the size cap), the call has no intent, and older messages and the session cache are not used as a fallback. It is gated as if no intent existed, and a diagnostic goes to stderr.
- If the canonical location is redirected, the call also has no intent, and the file it leads to is not read. That means the location, or any directory between it and your home directory, is a symlink (or on Windows, a junction). This includes a `.gemini` directory symlinked from a dotfiles repository, which then gets no transcript intent. Your home directory itself may be a symlink.
- If the transcript is unavailable (wrong path, unreadable, or no user record in the scanned window), the transcript adds nothing. Only a turn-matched intent from an explicit `jev-guard ingest` can still apply.

Limits:

- An unusable latest record is not treated as a stop, because every long prompt would then hold every call. A stop that cannot be read is therefore not honored.
- Without a `Stop` hook, transcript intent lasts until the next user message, including for background work after the reply ends.
- Transcript text can include anything you pasted, like any other prompt.

Agent access to the transcript is denied, within its limits (see [Antigravity transcript guard](#antigravity-transcript-guard)).

## Intent policy matrix

When context awareness is enabled and an intent is ingested, TypeSafe AI classifies `intent_alignment` into three categories:

| Action risk / blast radius | Unprompted / contrary intent | Incidental / unclear intent | Explicitly requested by user |
| :--- | :--- | :--- | :--- |
| **Catastrophic deletion** (`score > 2.5`, `catastrophic_deletion`) | **DENY** | **DENY** | **`force_ask`** |
| **Moderate blast radius** (`score 1.2 – 2.4`, e.g. `rm -rf dist`) | **`force_ask`** | **`force_ask`** | **`ALLOW`** |
| **Sensitive file access** (`.env`, `.pem`, credentials) | **`force_ask`** | **`force_ask`** | **`ALLOW`** |
| **Privilege / persistence** (system profile edits, root escalation) | **DENY** | **DENY** | **`force_ask`** |
| **Workspace boundary escape** (`../../` traversal) | **`force_ask`** | **`force_ask`** | **`force_ask`** |
| **Anti-tampering** (`~/.jevguard/` access) | **DENY** | **DENY** | **DENY** |

For file-path tools, a deterministic local proof that the target is inside the workspace overrides the model's containment probability. The local proof applies only to `Read`, `Edit`, `MultiEdit`, `Write`, `NotebookEdit`, `write_to_file`, `replace_file_content`, and `view_file`, and only when the call has a single path argument. It never applies to execution-sensitive paths: the directories `.git`, `.github`, `.husky`, `.devcontainer`, `.claude`, `.codex`, `.cursor`, `.gemini`, `.agent`, `.agents`, `.windsurf`, `.vscode`, `.idea`, and `.jevguard`, and the files `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.mcp.json`, and `.envrc` (matched case-insensitively). Those always use the model's containment score. For other paths, a low `IsWorkspaceContained` score alone does not trigger a boundary-escape prompt. Shell commands are unaffected.

> [!IMPORTANT]
> **The catastrophic ceiling.** Even when you explicitly ask for it, an action with a catastrophic blast radius (such as `rm -rf /` or recursive drive formatting) never runs automatically. `jev-guard` downgrades it from `DENY` to `force_ask`: Antigravity prompts you, so you have the final veto, while Claude Code and Codex block it. This rule takes precedence over all violation categories, including credential access.
>
> Explicit authorization also requires high confidence from TypeSafe AI (`intent_confidence >= 0.70`); lower-confidence classifications fall back to confirmation (`force_ask` / `ASK`). When an intent is active, the fast path defers all sensitive file access (`.env`, `.pem`, and so on) to semantic evaluation, so read tools and trusted commands cannot allow it early.

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
