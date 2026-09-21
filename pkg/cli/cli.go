package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"jev-guard/pkg/harness"
	"jev-guard/pkg/session"
)

// Version information configured at compile-time or defaulted.
var (
	Version = "0.1.0"
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
		if len(args) > 1 && strings.EqualFold(args[1], "clear") {
			return r.handleClearIntent(args[2:])
		}
		if len(args) > 1 && strings.EqualFold(args[1], "status") {
			return r.handleStatus()
		}
		return r.handleUnknown(args[0] + " " + args[1])
	case "status":
		return r.handleStatus()
	default:
		return r.handleUnknown(args[0])
	}
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
		switch strings.ToLower(args[i]) {
		case "-s", "--session", "--session-id", "--session_id":
			if i+1 < len(args) {
				sessionID = args[i+1]
				i++
			}
		case "-t", "--turn", "--turn-id", "--turn_id":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &turnID)
				i++
			}
		case "-p", "--prompt":
			if i+1 < len(args) {
				prompt = args[i+1]
				i++
			}
		}
	}

	// If prompt not provided in CLI flags, attempt to read piped JSON from Stdin
	if prompt == "" && r.Stdin != nil {
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

	if session.IsNegativeIntent(prompt) {
		fmt.Fprintf(r.Stdout, "Abort signal recorded for session '%s' (active intent cancelled)\n", sessionID)
	} else {
		fmt.Fprintf(r.Stdout, "Session intent recorded for session '%s' (turn: %d)\n", sessionID, turnID)
	}

	return ActionHandled, 0
}

func (r *Runner) handleClearIntent(args []string) (Action, int) {
	var sessionID string
	clearAll := false

	for i := 0; i < len(args); i++ {
		switch strings.ToLower(args[i]) {
		case "-s", "--session", "--session-id", "--session_id":
			if i+1 < len(args) {
				sessionID = args[i+1]
				i++
			}
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
  ingest          Ingest active user prompt/intent into session cache
  clear-intent    Clear active user intent for a session (or all sessions)
  cache clear     Alias for clear-intent
  status          Display active sessions and jev-guard environment status

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
  via 'jev-guard ingest' (invoked by UserPromptSubmit or PreInvocation hooks)
  to authorize explicitly requested operations and prevent false denials.`
}
