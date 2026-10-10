package main

import (
	"context"
	"errors"
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
	"jev-guard/pkg/transcript"
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
		session.SetSessionTTL(cfg.IntentTTL())
		sessionID := call.SessionID
		if sessionID == "" {
			sessionID = "default"
		}
		if sessState, sessErr := session.LoadSession(sessionID); sessErr == nil && sessState != nil {
			if sessState.Aborted {
				return holdAborted(call, cfg, "Action held: an active abort/stop signal was recorded for this session")
			}
			if intent := resolveUserIntent(call.TurnID, sessState.TurnID, sessState.Prompt); intent != "" {
				call.UserIntent = intent
			}
		}
		if home, homeErr := os.UserHomeDir(); homeErr == nil && applyTranscriptIntent(call, cfg, home) {
			return holdAborted(call, cfg, "Action held: the latest user request in the Antigravity transcript is an abort/stop command")
		}
	}

	result := executeGateEvaluation(call, cfg)

	if auditErr := cfg.LogAudit(call, result); auditErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to write audit entry: %v\n", auditErr)
	}

	return outputHarnessVerdict(call, *result)
}

// holdAborted logs and returns a force_ask verdict for an aborted session or stop request.
func holdAborted(call *harness.NormalizedToolCall, cfg *config.Config, reason string) int {
	result := &harness.EvaluationResult{
		Decision:   harness.DecisionForceAsk,
		Reason:     reason,
		Source:     "session_aborted",
		Confidence: 1.0,
	}
	_ = cfg.LogAudit(call, result)
	return outputHarnessVerdict(call, *applyAuditMode(result, cfg.Mode))
}

// applyTranscriptIntent reads the latest user request from the Antigravity transcript when
// the harness and the antigravity_transcript_intent setting allow it.
// It sets call.UserIntent and returns false normally, or returns true when that request
// is a stop/abort command. Any error leaves the call without intent (stateless gating).
func applyTranscriptIntent(call *harness.NormalizedToolCall, cfg *config.Config, home string) bool {
	if call.Harness != harness.HarnessAntigravity || !cfg.IsAntigravityTranscriptIntentEnabled() {
		return false
	}
	text, err := transcript.LatestUserInput(call.TranscriptPath, call.SessionID, home)
	if err != nil {
		if !errors.Is(err, transcript.ErrNoUserInput) {
			fmt.Fprintf(os.Stderr, "jev-guard: antigravity transcript intent unavailable: %v\n", err)
		}
		return false
	}
	if session.IsNegativeIntent(text) {
		return true
	}
	call.UserIntent = text
	return false
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
	judgments, evalErr := performSemanticEvaluation(call, cfg)

	pol := policy.NewDefaultPolicy()
	resolved := pol.Resolve(judgments, contained, evalErr)

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
