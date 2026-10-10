package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"jev-guard/pkg/config"
	"jev-guard/pkg/harness"
	"jev-guard/pkg/session"
)

// Version information configured at compile-time or defaulted.
var (
	Version = "0.2.0"
	Commit  = "none"
	Date    = "unknown"
)

// Action indicates whether the CLI handled the invocation or if gate evaluation should proceed.
type Action int

const (
	// ActionExecuteGate indicates standard tool-call evaluation should run against stdin.
	ActionExecuteGate Action = iota
	// ActionHandled indicates the CLI handled the request (e.g. --help, --version) and should terminate.
	ActionHandled
)

// Runner orchestrates command-line flag evaluation and terminal stream inspection.
type Runner struct {
	Stdout     io.Writer
	Stderr     io.Writer
	Stdin      io.Reader
	IsTerminal func() bool
	// HTTPClient is used by doctor's network check; nil uses a default client.
	HTTPClient *http.Client
}

// NewRunner creates a Runner with injected I/O streams and terminal detector.
func NewRunner(stdout, stderr io.Writer, isTerminal func() bool) *Runner {
	return &Runner{
		Stdout:     stdout,
		Stderr:     stderr,
		Stdin:      os.Stdin,
		IsTerminal: isTerminal,
	}
}

// DefaultIsTerminal checks whether os.Stdin is an interactive character device.
func DefaultIsTerminal() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

// EvaluateArgs examines command line arguments and terminal state to determine CLI workflow.
func (r *Runner) EvaluateArgs(args []string) (Action, int) {
	if len(args) > 0 {
		return r.handleArgs(args)
	}

	if r.IsTerminal != nil && r.IsTerminal() {
		return r.handleTerminal()
	}

	return ActionExecuteGate, 0
}

func (r *Runner) handleArgs(args []string) (Action, int) {
	switch strings.ToLower(args[0]) {
	case "-v", "--version", "-version", "version":
		return r.printVersion()
	case "-h", "--help", "-help", "help":
		return r.printHelp()
	case "ingest":
		return r.handleIngest(args[1:])
	case "clear-intent", "clear_intent":
		return r.handleClearIntent(args[1:])
	case "cache":
		if len(args) == 1 {
			return r.handleStatus()
		}
		if strings.EqualFold(args[1], "clear") {
			return r.handleClearIntent(args[2:])
		}
		if strings.EqualFold(args[1], "status") {
			return r.handleStatus()
		}
		return r.handleUnknown(args[0] + " " + args[1])
	case "status":
		return r.handleStatus()
	case "config":
		return r.handleConfig(args[1:])
	case "init":
		return r.handleInit(args[1:])
	case "doctor":
		return r.handleDoctor(args[1:])
	default:
		return r.handleUnknown(args[0])
	}
}

func (r *Runner) handleConfig(args []string) (Action, int) {
	if len(args) == 0 {
		fmt.Fprintln(r.Stderr, "Error: config requires show, trust, or untrust")
		return ActionHandled, 1
	}
	switch strings.ToLower(args[0]) {
	case "show":
		return r.handleConfigShow()
	case "trust":
		return r.handleConfigTrust(args[1:])
	case "untrust":
		return r.handleConfigUntrust(args[1:])
	default:
		fmt.Fprintf(r.Stderr, "Error: unknown config command %q\n", args[0])
		return ActionHandled, 1
	}
}

func (r *Runner) handleConfigShow() (Action, int) {
	cwd, _ := os.Getwd()
	cfg := config.LoadConfig(cwd)
	fmt.Fprintln(r.Stdout, "jev-guard effective configuration:")
	fmt.Fprintf(r.Stdout, "  User config:          %s\n", cfg.UserConfigPath)
	fmt.Fprintf(r.Stdout, "  Trust registry:       %s\n", config.TrustRegistryPath())
	fmt.Fprintf(r.Stdout, "  Mode:                 %s (%s)\n", cfg.Mode, cfg.Sources["mode"])
	fmt.Fprintf(r.Stdout, "  Base URL:             %s (%s)\n", effectiveBaseURL(cfg.BaseURL), cfg.Sources["base_url"])
	fmt.Fprintf(r.Stdout, "  API key:              %s (%s)\n", configuredValue(cfg.APIKey), cfg.Sources["api_key"])
	fmt.Fprintf(r.Stdout, "  Model:                %s (%s)\n", effectiveValue(cfg.Model, "jev-latest"), cfg.Sources["model"])
	fmt.Fprintf(r.Stdout, "  Timeout:              %d ms (%s)\n", effectiveTimeout(cfg.TimeoutMs), cfg.Sources["timeout_ms"])
	fmt.Fprintf(r.Stdout, "  Fastpath enabled:     %t (%s)\n", cfg.IsFastpathEnabled(), cfg.Sources["fastpath_enabled"])
	fmt.Fprintf(r.Stdout, "  Context awareness:    %t (%s)\n", cfg.IsContextAwarenessEnabled(), cfg.Sources["context_awareness_enabled"])
	fmt.Fprintf(r.Stdout, "  Sensitive files:      %d patterns (%s)\n", len(cfg.SensitiveFiles), cfg.Sources["sensitive_files"])
	fmt.Fprintf(r.Stdout, "  Trusted commands:     %d prefixes (%s)\n", len(cfg.TrustedCommands), cfg.Sources["trusted_commands"])
	if file := config.FindProjectConfigInDirectory(cwd); file != "" {
		if info, err := config.InspectProjectConfig(file); err == nil {
			trustState := "not trusted"
			if info.Trusted {
				trustState = "trusted for this exact SHA-256"
			}
			fmt.Fprintf(r.Stdout, "  Project config:       %s (%s)\n", info.ConfigPath, trustState)
			if info.TrustIssue != "" {
				fmt.Fprintf(r.Stdout, "  Trust registry:       %s\n", info.TrustIssue)
			}
			if len(info.IgnoredKeys) > 0 {
				fmt.Fprintf(r.Stdout, "  Ignored project keys: %s\n", strings.Join(info.IgnoredKeys, ", "))
			}
		}
	}
	for _, diagnostic := range cfg.Diagnostics {
		fmt.Fprintf(r.Stderr, "jev-guard: %s\n", diagnostic)
	}
	return ActionHandled, 0
}

func (r *Runner) handleConfigTrust(args []string) (Action, int) {
	info, err := inspectCLIProjectConfig(args)
	if err != nil {
		fmt.Fprintf(r.Stderr, "Error: %v\n", err)
		return ActionHandled, 1
	}
	printTrustProposal(r.Stdout, info)
	return ActionHandled, 0
}

func (r *Runner) handleConfigUntrust(args []string) (Action, int) {
	info, err := inspectCLIProjectConfig(args)
	if err != nil {
		fmt.Fprintf(r.Stderr, "Error: %v\n", err)
		return ActionHandled, 1
	}
	fmt.Fprintf(r.Stdout, "Project config: %s\nProject root: %s\n", info.ConfigPath, info.ProjectRoot)
	if info.Trusted {
		fmt.Fprintf(r.Stdout, "Current digest %s is trusted. Remove the registry entry with this project_root and config_path to revoke it.\n", info.SHA256)
	} else {
		fmt.Fprintln(r.Stdout, "Current digest is not trusted. Remove any registry entry with this project_root and config_path to revoke older digests.")
	}
	fmt.Fprintf(r.Stdout, "Trust registry: %s\n", config.TrustRegistryPath())
	fmt.Fprintln(r.Stdout, "This command does not edit user-owned files; edit the registry manually to revoke trust.")
	return ActionHandled, 0
}

func inspectCLIProjectConfig(args []string) (*config.ProjectConfigInfo, error) {
	path := ""
	if len(args) > 0 {
		path = args[0]
	} else if cwd, err := os.Getwd(); err == nil {
		path = config.FindProjectConfigInDirectory(cwd)
	}
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("no project config found; pass a config file or directory path")
	}
	return config.InspectProjectConfig(path)
}

func printTrustProposal(out io.Writer, info *config.ProjectConfigInfo) {
	entry, _ := json.MarshalIndent(info.TrustRecord, "", "  ")
	fmt.Fprintf(out, "Project config: %s\n", info.ConfigPath)
	fmt.Fprintf(out, "Project root: %s\nSHA-256: %s\n", info.ProjectRoot, info.SHA256)
	fmt.Fprintf(out, "Additive sensitive_files: %v\n", info.SensitiveFiles)
	if info.TrustIssue != "" {
		fmt.Fprintf(out, "Existing trust registry status: %s\n", info.TrustIssue)
	}
	if len(info.IgnoredKeys) > 0 {
		fmt.Fprintf(out, "Ignored project keys: %s\n", strings.Join(info.IgnoredKeys, ", "))
	}
	fmt.Fprintf(out, "Trust record to add to %s:\n%s\n", config.TrustRegistryPath(), entry)
	fmt.Fprintln(out, "The registry is user-owned. Review the file and add this record manually; this command does not grant trust.")
}

func configuredValue(value string) string {
	if value == "" {
		return "not configured"
	}
	return "configured"
}

func effectiveValue(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func effectiveTimeout(timeoutMs int) int {
	if timeoutMs <= 0 {
		return 1500
	}
	return timeoutMs
}

func effectiveBaseURL(value string) string {
	if value == "" {
		return "https://api.typesafe.ai/v1/systemone"
	}
	return value
}

func (r *Runner) printVersion() (Action, int) {
	if Commit != "none" && Date != "unknown" {
		fmt.Fprintf(r.Stdout, "jev-guard version %s (commit: %s, built: %s)\n", Version, Commit, Date)
	} else {
		fmt.Fprintf(r.Stdout, "jev-guard version %s\n", Version)
	}
	return ActionHandled, 0
}

func (r *Runner) printHelp() (Action, int) {
	fmt.Fprintln(r.Stdout, helpMessage())
	return ActionHandled, 0
}

func (r *Runner) handleTerminal() (Action, int) {
	fmt.Fprintln(r.Stdout, helpMessage())
	fmt.Fprintln(r.Stdout, "Notice: jev-guard expects tool call payload JSON on standard input.")
	fmt.Fprintln(r.Stdout, "Run 'jev-guard --help' for usage, or pipe a JSON payload: cat payload.json | jev-guard")
	return ActionHandled, 0
}

func (r *Runner) handleUnknown(arg string) (Action, int) {
	fmt.Fprintf(r.Stderr, "Error: unrecognized flag or command: %s\n\n", arg)
	fmt.Fprintln(r.Stderr, helpMessage())
	return ActionHandled, 1
}

func (r *Runner) handleIngest(args []string) (Action, int) {
	var sessionID string
	var turnID int
	var prompt string

	for i := 0; i < len(args); i++ {
		if val, ok := parseFlagValue(args, &i, "-s", "--session", "--session-id", "--session_id"); ok {
			sessionID = val
			continue
		}
		if val, ok := parseFlagValue(args, &i, "-t", "--turn", "--turn-id", "--turn_id"); ok {
			fmt.Sscanf(val, "%d", &turnID)
			continue
		}
		if val, ok := parseFlagValue(args, &i, "-p", "--prompt"); ok {
			prompt = val
			continue
		}
	}

	// If prompt not provided in CLI flags, attempt to read piped JSON from Stdin
	if prompt == "" && r.Stdin != nil {
		if r.IsTerminal != nil && r.IsTerminal() {
			fmt.Fprintln(r.Stderr, "Error: ingest requires a non-empty prompt via --prompt or piped JSON payload on stdin")
			return ActionHandled, 1
		}
		stdinBytes, err := io.ReadAll(r.Stdin)
		if err != nil {
			fmt.Fprintf(r.Stderr, "Error reading stdin: %v\n", err)
		} else if len(strings.TrimSpace(string(stdinBytes))) > 0 {
			parsedState, parseErr := harness.ParseIngestPayload(stdinBytes)
			if parseErr != nil {
				fmt.Fprintf(r.Stderr, "Error parsing ingest payload: %v (received: %q)\n", parseErr, string(stdinBytes))
			} else if parsedState != nil {
				if sessionID == "" {
					sessionID = parsedState.SessionID
				}
				if turnID == 0 {
					turnID = parsedState.TurnID
				}
				if prompt == "" {
					prompt = parsedState.Prompt
				}
			}
		}
	}

	if strings.TrimSpace(prompt) == "" {
		fmt.Fprintln(r.Stderr, "Error: ingest requires a non-empty prompt via --prompt or piped JSON payload on stdin")
		return ActionHandled, 1
	}

	if sessionID == "" {
		sessionID = "default"
	}

	state := &session.SessionState{
		SessionID: sessionID,
		TurnID:    turnID,
		Prompt:    prompt,
	}

	if err := session.SaveSession(state); err != nil {
		fmt.Fprintf(r.Stderr, "Error: failed to save session intent: %v\n", err)
		return ActionHandled, 1
	}

	// Write confirmation to Stderr so stdout remains empty and does not pollute Claude Code prompts
	if session.IsNegativeIntent(prompt) {
		fmt.Fprintf(r.Stderr, "Abort signal recorded for session '%s' (active intent cancelled)\n", sessionID)
	} else {
		fmt.Fprintf(r.Stderr, "Session intent recorded for session '%s' (turn: %d)\n", sessionID, turnID)
	}

	return ActionHandled, 0
}

func (r *Runner) handleClearIntent(args []string) (Action, int) {
	var sessionID string
	clearAll := false

	for i := 0; i < len(args); i++ {
		if val, ok := parseFlagValue(args, &i, "-s", "--session", "--session-id", "--session_id"); ok {
			sessionID = val
			continue
		}
		switch strings.ToLower(args[i]) {
		case "-a", "--all":
			clearAll = true
		}
	}

	if sessionID != "" && !clearAll {
		if err := session.ClearSession(sessionID); err != nil {
			fmt.Fprintf(r.Stderr, "Error: failed to clear session: %v\n", err)
			return ActionHandled, 1
		}
		fmt.Fprintf(r.Stdout, "Session intent cleared for session '%s'\n", sessionID)
		return ActionHandled, 0
	}

	if err := session.ClearAllSessions(); err != nil {
		fmt.Fprintf(r.Stderr, "Error: failed to clear all sessions: %v\n", err)
		return ActionHandled, 1
	}
	fmt.Fprintln(r.Stdout, "All active session intents cleared")
	return ActionHandled, 0
}

func (r *Runner) handleStatus() (Action, int) {
	homeDir := session.GetJevguardDir()
	sessionsDir := session.GetSessionsDir()

	list, err := session.ListSessions()
	if err != nil {
		fmt.Fprintf(r.Stderr, "Error reading sessions: %v\n", err)
		return ActionHandled, 1
	}

	fmt.Fprintln(r.Stdout, "jev-guard status:")
	fmt.Fprintf(r.Stdout, "  Home Directory:     %s\n", homeDir)
	fmt.Fprintf(r.Stdout, "  Sessions Directory: %s\n", sessionsDir)
	fmt.Fprintf(r.Stdout, "  Active Sessions:    %d\n", len(list))

	for _, s := range list {
		status := "Active"
		if s.Aborted {
			status = "Aborted"
		}
		promptPreview := s.Prompt
		if len(promptPreview) > 60 {
			promptPreview = promptPreview[:57] + "..."
		}
		fmt.Fprintf(r.Stdout, "  - [%s] Status: %s, Turn: %d, Updated: %s\n",
			s.SessionID, status, s.TurnID, s.UpdatedAt.Format("15:04:05"))
		if promptPreview != "" {
			fmt.Fprintf(r.Stdout, "    Prompt: %q\n", promptPreview)
		}
	}

	return ActionHandled, 0
}

func helpMessage() string {
	return `jev-guard - High-speed, cross-agent safety gate plugin

Usage:
  jev-guard [command] [flags]
  <payload-json> | jev-guard

Commands:
  init            Configure agent hooks in the current project
  ingest          Ingest active user prompt/intent into session cache
  clear-intent    Clear active user intent for a session (or all sessions)
  cache clear     Alias for clear-intent
  status          Display active sessions and jev-guard environment status
  doctor          Diagnose environment, network, and hook setup (--offline skips network)
  config show     Show effective policy and its source without printing secrets
  config trust    Print a digest-bound registry record for manual user approval
  config untrust  Show which user registry entry to remove to revoke trust

Flags:
  -h, --help       Show help and usage information
  -v, --version    Show version information

Ingest Flags:
  -s, --session <id>   Session / Conversation ID (defaults to "default")
  -t, --turn <num>     Turn / Invocation sequence number
  -p, --prompt <text>  Active user prompt text (or pipe payload JSON via stdin)

Clear-Intent Flags:
  -s, --session <id>   Session ID to clear (omitting clears all sessions)
  -a, --all            Clear all active session caches

Description:
  jev-guard intercepts AI agent tool calls from Claude Code, Codex CLI,
  and Antigravity. It reads tool call payloads from standard input (stdin)
  and outputs evaluation verdicts (ALLOW, ASK, or DENY).

  With context awareness enabled, jev-guard can ingest active user prompts
  via 'jev-guard ingest' (invoked by Claude Code's UserPromptSubmit hook)
  to authorize explicitly requested operations and prevent false denials.`
}

// parseFlagValue extracts the value for a given flag either from --flag=value or from a separate next argument.
func parseFlagValue(args []string, i *int, flagNames ...string) (string, bool) {
	arg := args[*i]
	lower := strings.ToLower(arg)

	for _, name := range flagNames {
		lowerName := strings.ToLower(name)
		if lower == lowerName {
			if *i+1 < len(args) {
				*i++
				return strings.Trim(args[*i], `"'`), true
			}
			return "", true
		}
		prefix := lowerName + "="
		if strings.HasPrefix(lower, prefix) {
			rawVal := arg[len(prefix):]
			return strings.Trim(rawVal, `"'`), true
		}
	}
	return "", false
}
