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
	runner.Eval = runEval
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
				result := abortedSessionResult()
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

// abortedSessionResult is the verdict the hook returns while an abort/stop signal is active.
func abortedSessionResult() *harness.EvaluationResult {
	return &harness.EvaluationResult{
		Decision:   harness.DecisionForceAsk,
		Reason:     "Action held: an active abort/stop signal was recorded for this session",
		Source:     "session_aborted",
		Confidence: 1.0,
	}
}

func readStandardInput() ([]byte, error) {
	return io.ReadAll(os.Stdin)
}

// gateTrace records the intermediate results of the gate pipeline so that both the
// hook path and `jev-guard eval --explain` share a single implementation.
type gateTrace struct {
	FastpathRan      bool
	Fastpath         *harness.EvaluationResult
	Contained        bool
	SemanticRan      bool
	Judgments        *evaluator.JevJudgments
	EvalErr          error
	WouldSendToJudge bool
	Final            *harness.EvaluationResult
}

func executeGateEvaluation(call *harness.NormalizedToolCall, cfg *config.Config) *harness.EvaluationResult {
	return traceGateEvaluation(call, cfg, false).Final
}

// traceGateEvaluation runs boundary, fastpath, semantic evaluation, and policy.
// When offline is true the TypeSafe call is skipped and Final is nil if fastpath had no verdict.
func traceGateEvaluation(call *harness.NormalizedToolCall, cfg *config.Config, offline bool) *gateTrace {
	trace := &gateTrace{}
	resolver, _ := boundary.NewResolver(call.WorkspaceRoots, call.Cwd)
	var checker fastpath.BoundaryChecker
	if resolver != nil {
		checker = resolver
	}
	trace.Contained = checkWorkspaceBoundary(call, resolver)

	if cfg.IsFastpathEnabled() {
		trace.FastpathRan = true
		fastFilter := fastpath.NewFilter(checker, cfg)
		if fastResult := fastFilter.Evaluate(call); fastResult != nil {
			trace.Fastpath = fastResult
			trace.Final = applyAuditMode(fastResult, cfg.Mode)
			return trace
		}
	}

	if offline {
		trace.WouldSendToJudge = true
		return trace
	}

	trace.SemanticRan = true
	trace.Judgments, trace.EvalErr = performSemanticEvaluation(call, cfg)

	pol := policy.NewDefaultPolicy()
	resolved := pol.Resolve(trace.Judgments, trace.Contained, trace.EvalErr)
	trace.Final = applyAuditMode(resolved, cfg.Mode)
	return trace
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
