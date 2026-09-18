package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
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
	IsTerminal func() bool
}

// NewRunner creates a Runner with injected I/O streams and terminal detector.
func NewRunner(stdout, stderr io.Writer, isTerminal func() bool) *Runner {
	return &Runner{
		Stdout:     stdout,
		Stderr:     stderr,
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

func helpMessage() string {
	return `jev-guard - High-speed, cross-agent safety gate plugin

Usage:
  jev-guard [flags]
  <payload-json> | jev-guard

Flags:
  -h, --help       Show help and usage information
  -v, --version    Show version information

Description:
  jev-guard intercepts AI agent tool calls from Claude Code, Codex CLI,
  and Antigravity. It reads tool call payloads from standard input (stdin)
  and outputs evaluation verdicts (ALLOW, ASK, or DENY).`
}
