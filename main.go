package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"jev-guard/pkg/boundary"
	"jev-guard/pkg/cli"
	"jev-guard/pkg/config"
	"jev-guard/pkg/evaluator"
	"jev-guard/pkg/fastpath"
	"jev-guard/pkg/harness"
	"jev-guard/pkg/policy"
	"jev-guard/pkg/session"
)

func main() {
	if err := config.EnsureUserConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "jev-guard: cannot initialize user config: %v\n", err)
		os.Exit(2)
	}
	runner := cli.NewRunner(os.Stdout, os.Stderr, cli.DefaultIsTerminal)
	action, exitCode := runner.EvaluateArgs(os.Args[1:])
	if action == cli.ActionHandled {
		os.Exit(exitCode)
	}

	exitCode = runGate()
	os.Exit(exitCode)
}

// runGate orchestrates ingestion, local fast-path, semantic evaluation, and response delivery.
func runGate() int {
	inputBytes, err := readStandardInput()
	if err != nil {
		return handleFatalError(nil, "Failed to read standard input", err)
	}

	call, err := harness.ParsePayload(inputBytes)
	if err != nil {
		return handleFatalError(nil, "Failed to parse tool call payload", err)
	}

	cfg := config.LoadConfigForCall(call)
	for _, diagnostic := range cfg.Diagnostics {
		fmt.Fprintf(os.Stderr, "jev-guard: %s\n", diagnostic)
	}

	if cfg.IsContextAwarenessEnabled() {
		sessionID := call.SessionID
		if sessionID == "" {
			sessionID = "default"
		}
		if sessState, sessErr := session.LoadSession(sessionID); sessErr == nil && sessState != nil {
			if sessState.Aborted {
				result := &harness.EvaluationResult{
					Decision:   harness.DecisionForceAsk,
					Reason:     "Action held: an active abort/stop signal was recorded for this session",
					Source:     "session_aborted",
					Confidence: 1.0,
				}
				_ = cfg.LogAudit(call, result)
				return outputHarnessVerdict(call, *applyAuditMode(result, cfg.Mode))
			}
			if intent := resolveUserIntent(call.TurnID, sessState.TurnID, sessState.Prompt); intent != "" {
				call.UserIntent = intent
			}
		}
	}

	result := executeGateEvaluation(call, cfg)

	if auditErr := cfg.LogAudit(call, result); auditErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to write audit entry: %v\n", auditErr)
	}

	return outputHarnessVerdict(call, *result)
}

func readStandardInput() ([]byte, error) {
	return io.ReadAll(os.Stdin)
}

func executeGateEvaluation(call *harness.NormalizedToolCall, cfg *config.Config) *harness.EvaluationResult {
	resolver, _ := boundary.NewResolver(call.WorkspaceRoots, call.Cwd)
	var checker fastpath.BoundaryChecker
	if resolver != nil {
		checker = resolver
	}

	if cfg.IsFastpathEnabled() {
		fastFilter := fastpath.NewFilter(checker, cfg)
		if fastResult := fastFilter.Evaluate(call); fastResult != nil {
			return applyAuditMode(fastResult, cfg.Mode)
		}
	}

	contained := checkWorkspaceBoundary(call, resolver)
	pathVerified := isLocalPathVerified(call, contained)
	judgments, evalErr := performSemanticEvaluation(call, cfg)

	pol := policy.NewDefaultPolicy()
	resolved := pol.ResolveWithEvidence(judgments, policy.BoundaryEvidence{Contained: contained, PathVerified: pathVerified}, evalErr)

	return applyAuditMode(resolved, cfg.Mode)
}

func checkWorkspaceBoundary(call *harness.NormalizedToolCall, resolver *boundary.Resolver) bool {
	if strings.TrimSpace(call.TargetPath) == "" {
		return true
	}
	if resolver == nil {
		return false
	}
	contained, err := resolver.IsPathContained(call.TargetPath, call.Cwd)
	if err != nil {
		return false
	}
	return contained
}

// singleTargetFileTools maps each allowlisted file tool to its canonical path
// argument. A call is only verified when TargetPath came from that argument
// and no other path-like argument is present, so a payload cannot smuggle a
// higher-priority in-workspace key past the resolver while the tool acts on
// its real (out-of-workspace) argument.
var singleTargetFileTools = map[string]string{
	"Read": "file_path", "Edit": "file_path", "MultiEdit": "file_path", "Write": "file_path",
	"NotebookEdit":  "notebook_path",
	"write_to_file": "TargetFile", "replace_file_content": "TargetFile", "view_file": "AbsolutePath",
}

// executionSensitiveDirs are in-workspace directories whose contents execute
// code or configure agents/hooks; writes there are never locally verified.
var executionSensitiveDirs = map[string]bool{
	".git": true, ".github": true, ".husky": true, ".devcontainer": true,
	".claude": true, ".codex": true, ".cursor": true, ".gemini": true, ".agent": true,
	".agents": true, ".windsurf": true, ".vscode": true, ".idea": true, ".jevguard": true,
}

// executionSensitiveFiles are basenames of agent instruction/config files.
var executionSensitiveFiles = map[string]bool{
	"claude.md": true, "agents.md": true, "gemini.md": true, ".mcp.json": true, ".envrc": true,
}

// isExecutionSensitivePath reports whether target lies in a directory or file
// that runs code or configures the agent. Matching is case-insensitive and
// accepts both slash styles.
func isExecutionSensitivePath(target string) bool {
	segments := strings.Split(strings.ReplaceAll(target, "\\", "/"), "/")
	for i, seg := range segments {
		seg = strings.ToLower(strings.TrimSpace(seg))
		if executionSensitiveDirs[seg] {
			return true
		}
		if i == len(segments)-1 && executionSensitiveFiles[seg] {
			return true
		}
	}
	return false
}

// isLocalPathVerified reports whether the local resolver positively proved a
// filesystem target is inside the workspace. Shell commands, empty targets
// (where checkWorkspaceBoundary is vacuously true), URLs, mixed path
// arguments and execution-sensitive paths never qualify.
func isLocalPathVerified(call *harness.NormalizedToolCall, contained bool) bool {
	key, ok := singleTargetFileTools[call.ToolName]
	target := strings.TrimSpace(call.TargetPath)
	if !contained || !ok || target == "" || strings.TrimSpace(call.Command) != "" || strings.Contains(target, "://") {
		return false
	}
	raw, isString := call.RawArgs[key].(string)
	if !isString || strings.TrimSpace(raw) != target {
		return false
	}
	for _, k := range harness.PathArgKeys {
		if k == key {
			continue
		}
		if _, present := call.RawArgs[k]; present {
			return false
		}
	}
	return !isExecutionSensitivePath(target)
}

func performSemanticEvaluation(call *harness.NormalizedToolCall, cfg *config.Config) (*evaluator.JevJudgments, error) {
	client := evaluator.NewClient(cfg.APIKey, cfg.BaseURL, cfg.Model, cfg.Timeout)
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	return client.Evaluate(ctx, call)
}

func applyAuditMode(result *harness.EvaluationResult, mode string) *harness.EvaluationResult {
	if mode != "audit" {
		return result
	}

	if result.Decision == harness.DecisionDeny || result.Decision == harness.DecisionAsk || result.Decision == harness.DecisionForceAsk {
		return &harness.EvaluationResult{
			Decision:   harness.DecisionAllow,
			Reason:     fmt.Sprintf("[AUDIT-MODE: %s] %s", result.Decision, result.Reason),
			Source:     result.Source,
			Confidence: result.Confidence,
		}
	}

	return result
}

func outputHarnessVerdict(call *harness.NormalizedToolCall, result harness.EvaluationResult) int {
	exitCode, output, err := harness.FormatResponseForCall(call, result)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error formatting harness response: %v\n", err)
		return 1
	}

	if exitCode == 2 {
		fmt.Fprintf(os.Stderr, "%s\n", string(output))
		return exitCode
	}

	fmt.Println(string(output))
	return exitCode
}

func handleFatalError(call *harness.NormalizedToolCall, msg string, err error) int {
	res := harness.EvaluationResult{
		Decision: harness.DecisionAsk,
		Reason:   fmt.Sprintf("%s: %v", msg, err),
		Source:   "fatal_error",
	}
	return outputHarnessVerdict(call, res)
}

func resolveUserIntent(callTurnID, sessionTurnID int, sessionPrompt string) string {
	if callTurnID == 0 || sessionTurnID == 0 || callTurnID == sessionTurnID {
		return sessionPrompt
	}
	return ""
}
