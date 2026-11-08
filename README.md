# jev-guard

[![CI](https://github.com/ClemensSchartmueller/jev-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/ClemensSchartmueller/jev-guard/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ClemensSchartmueller/jev-guard)](https://github.com/ClemensSchartmueller/jev-guard/releases)
[![npm](https://img.shields.io/npm/v/@clemensschartmueller/jev-guard)](https://www.npmjs.com/package/@clemensschartmueller/jev-guard)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE.md)

**A safety gate for AI coding agents.** `jev-guard` checks every shell command, file write, and file read your agent attempts *before* it runs, and blocks or asks you about the risky ones.

It works with **Claude Code**, **Codex CLI**, and **Antigravity**, including in autonomous modes such as `--dangerously-skip-permissions` and `--yolo`.

```text
$ jev-guard eval --cmd "git status"
ALLOW: Trusted read-only operation verified by fast-path (source: fastpath_trusted)

$ jev-guard eval --cmd "cat .env"
ASK: Access to sensitive file or credential pattern: .env (source: fastpath_sensitive)

$ jev-guard eval --tool Read --target /etc/shadow
ASK: Target path escapes workspace boundaries: /etc/shadow (source: fastpath_boundary)
```

## Contents

- [Why jev-guard?](#why-jev-guard)
- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Common tasks](#common-tasks)
- [Configuration](#configuration)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

## Why jev-guard?

Coding agents are most useful when you let them run without approving every step, which is exactly when a mistaken `rm -rf`, a leaked `.env`, or a write outside your project does the most damage. `jev-guard` sits in the agent's hook pipeline and gives every tool call one of three verdicts:

| Verdict | Meaning | Example |
| :--- | :--- | :--- |
| ✅ **ALLOW** | Safe; runs without interrupting you. | `git status`, reading a source file |
| ⚠️ **ASK** | Needs a human decision. Antigravity prompts you; Claude Code and Codex block the call and tell the agent why. | Reading `.env`, writing `../outside.txt`, `rm -rf dist` |
| ⛔ **DENY** | Blocked. | Recursive deletion of your home directory, tampering with `jev-guard`'s own config |

Highlights:

- **Fast.** Most calls are decided locally in under a millisecond: credential files, workspace escapes, and trusted read-only commands.
- **Context-aware.** Ambiguous or destructive calls are judged by [TypeSafe AI](https://typesafe.ai)'s System One model, which also considers what you actually asked for. If you said *"delete the build folder"*, `rm -rf build` is not questioned again.
- **Fails safe.** If the API is unreachable, `jev-guard` asks instead of allowing.
- **Catastrophic ceiling.** Catastrophic actions never run automatically, even when you requested them.
- **Try before enforcing.** `audit` mode logs what *would* have been blocked without interrupting anything.

## Quick start

**Requirements:** Node.js 18+ for the one-command installer (the hooks themselves run a native binary), and a [TypeSafe AI](https://typesafe.ai) API key for semantic evaluation.

**1. Install and set up hooks.** From the project you want to protect:

```bash
npx --yes @clemensschartmueller/jev-guard@latest
```

This downloads the right binary for your platform, verifies its SHA-256 checksum, installs it to `~/.jevguard/bin`, and adds hooks for the agents it detects in the project (all supported agents if none are detected). Existing hooks are preserved, and running it again is safe.

**2. Add your API key.**

```bash
export TYPESAFE_API_KEY="your-typesafe-api-key"     # Linux / macOS
```

```powershell
$env:TYPESAFE_API_KEY = "your-typesafe-api-key"     # Windows PowerShell
```

The variable must be set in the environment you start your agent from. To make it persist, add the `export` line to your shell profile (e.g. `~/.bashrc` or `~/.zshrc`). Alternatively, put the key in `"api_key"` in `~/.jevguard/.jevguard.json`.

**3. Check the setup.**

```bash
~/.jevguard/bin/jev-guard doctor
```

On Windows, use `%USERPROFILE%\.jevguard\bin\jev-guard.exe doctor`. Fix anything marked `[FAIL]`, and make sure the `API key` line is not a warning: without a key, every call the local fast path cannot decide is held for confirmation. Then start your agent as usual.

> [!TIP]
> **Using Codex?** Run `/hooks` inside Codex once to review and trust the new hook; Codex does not run untrusted project hooks.
>
> **Want a specific agent or user-wide hooks?** Append flags after the package name: `--agent claude|codex|antigravity|all` and `--scope user`.

### Other installation methods

- **Prebuilt binaries:** download from [GitHub Releases](https://github.com/ClemensSchartmueller/jev-guard/releases) (checksums in `checksums.txt`), then run `jev-guard init` in your project.
- **From source:** clone this repository and run `./install.sh` (Linux/macOS) or `.\install.ps1` (Windows). Both install to `~/.jevguard/bin`. `install.sh` builds from source if Go is available, otherwise it downloads the latest release binary, and it only prints a reminder to add `~/.jevguard/bin` to your shell profile. `install.ps1` adds it to your user `PATH`. Then run `jev-guard init`.
- **Manual hook files:** see [docs/hooks.md](docs/hooks.md).

## How it works

```text
 Agent wants to run a tool
            │
            ▼
 ┌──────────────────────┐
 │  Anti-tampering      │── touches jev-guard's own files ──────▶ ⛔ DENY
 │  (always on)         │
 └──────────┬───────────┘
            │ everything else
            ▼
 ┌──────────────────────┐
 │  Local fast path     │── sensitive file / workspace escape ──▶ ⚠️ ASK
 │  (< 1 ms, offline)   │── trusted read-only command ─────────▶ ✅ ALLOW
 └──────────┬───────────┘
            │ anything else (writes, deletes, chained commands, web fetches)
            ▼
 ┌──────────────────────┐
 │  TypeSafe AI         │  judges blast radius, containment,
 │  System One (Jev)    │  violation type, and your stated intent
 └──────────┬───────────┘
            ▼
     ✅ ALLOW / ⚠️ ASK / ⛔ DENY  ──▶  translated into each agent's hook format
```

Each agent receives the verdict in its own protocol. In Claude Code and Codex, `ASK` becomes a block (exit code 2) with the reason sent to the agent, in every mode. That is also why bypass flags such as `--dangerously-skip-permissions` and `--yolo` cannot skip it. An `ALLOW` in Claude Code is sent as `permissionDecision: "allow"`, which pre-approves the tool call so Claude Code does not prompt for it. In Antigravity, `ASK` becomes `force_ask`, which prompts you even in Turbo mode.

The full rules, including the list of protected files, the intent policy matrix, and per-agent behavior, are in [docs/security-model.md](docs/security-model.md).

## Common tasks

| I want to… | Run |
| :--- | :--- |
| See why a command would be blocked | `jev-guard explain --cmd "rm -rf build"` |
| Test a decision without a network call | `jev-guard eval --cmd "cat .env" --offline` |
| Check my installation | `jev-guard doctor` |
| See the effective configuration | `jev-guard config show` |
| Try jev-guard without blocking anything | Set `"mode": "audit"` in `~/.jevguard/.jevguard.json` |
| Add hooks to another project | `jev-guard init` (inside that project) |

All commands and flags: [docs/cli.md](docs/cli.md).

## Configuration

All settings live in **`~/.jevguard/.jevguard.json`**, which is created with safe defaults on first run. The generated file already lists the built-in `sensitive_files` and `trusted_commands`. Entries you add to these lists are merged with the built-in defaults, which cannot be removed. Settings are deliberately kept outside your projects, so an agent or a cloned repository cannot weaken them.

```json
{
  "mode": "enforcing",
  "fastpath_enabled": true,
  "context_awareness_enabled": true,
  "audit_log_path": ".jevguard.log",
  "sensitive_files": [".env", "*.pem", "id_rsa"],
  "trusted_commands": ["git status", "git log"]
}
```

The most common changes:

- **`mode`**: `"enforcing"` (default) or `"audit"` (log only, never block).
- **`sensitive_files`**: extra file patterns that always need confirmation.
- **`trusted_commands`**: command prefixes allowed instantly without a network call.
- **`audit_log_path`**: write every decision to a JSONL log.

Every setting, the project-config trust model, and the audit log format are described in [docs/configuration.md](docs/configuration.md).

## Documentation

| Guide | Contents |
| :--- | :--- |
| [Configuration](docs/configuration.md) | All settings, operating modes, precedence, project config trust, audit log |
| [CLI reference](docs/cli.md) | Every command, `eval` flags, JSON output, exit codes |
| [Security model](docs/security-model.md) | Supported tools, fast path rules, TypeSafe evaluation, intent matrix, `.git/config` policy |
| [Manual hook setup](docs/hooks.md) | Hook JSON for Claude Code, Codex CLI, and Antigravity |

## Contributing

Contributions are welcome, whether that's support for another agent, better detection rules, documentation fixes, or bug reports. Please [open an issue](https://github.com/ClemensSchartmueller/jev-guard/issues) to discuss larger changes first.

To build and test locally (requires Go):

```bash
go test ./...
go build -o jev-guard .
```

## Disclaimer

This software is provided "as is", without warranty of any kind, express or implied. Neither TypeSafe AI (`typesafe.ai`), the `jev-guard` project, nor its contributors or maintainers are liable for any damages, losses, or claims arising from the use or performance of this hook (including, but not limited to, damages caused by misclassifications, false positives, or false negatives from Jev AI / TypeSafe AI). Users are responsible for evaluating and supervising automated agent tool calls in their own environments.

## License

[MIT](LICENSE.md)
