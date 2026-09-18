package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"jev-guard/pkg/boundary"
	"jev-guard/pkg/cli"
	"jev-guard/pkg/config"
	"jev-guard/pkg/evaluator"
	"jev-guard/pkg/fastpath"
	"jev-guard/pkg/harness"
	"jev-guard/pkg/policy"
)

func main() {
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
		return handleFatalError(harness.HarnessUnknown, "Failed to read standard input", err)
	}

	call, err := harness.ParsePayload(inputBytes)
	if err != nil {
		return handleFatalError(harness.HarnessUnknown, "Failed to parse tool call payload", err)
	}

	cfg := config.LoadConfig(call.Cwd)
	result := executeGateEvaluation(call, cfg)

	if auditErr := cfg.LogAudit(call, result); auditErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to write audit entry: %v\n", auditErr)
	}

	return outputHarnessVerdict(call.Harness, *result)
}

func readStandardInput() ([]byte, error) {
	return io.ReadAll(os.Stdin)
}

func executeGateEvaluation(call *harness.NormalizedToolCall, cfg *config.Config) *harness.EvaluationResult {
	fastFilter := fastpath.NewDefaultFilter()
	if fastResult := fastFilter.Evaluate(call); fastResult != nil {
		return applyAuditMode(fastResult, cfg.Mode)
	}

	contained := checkWorkspaceBoundary(call)
	judgments, evalErr := performSemanticEvaluation(call, cfg)

	pol := policy.NewDefaultPolicy()
	resolved := pol.Resolve(judgments, contained, evalErr)

	return applyAuditMode(resolved, cfg.Mode)
}

func checkWorkspaceBoundary(call *harness.NormalizedToolCall) bool {
	resolver, err := boundary.NewResolver(call.WorkspaceRoots, call.Cwd)
	if err != nil {
		return true // Fallback to allowing boundary evaluation to Jev
	}
	contained, err := resolver.IsPathContained(call.TargetPath, call.Cwd)
	if err != nil {
		return true
	}
	return contained
}

func performSemanticEvaluation(call *harness.NormalizedToolCall, cfg *config.Config) (*evaluator.JevJudgments, error) {
	client := evaluator.NewClient(cfg.APIKey, cfg.BaseURL, cfg.Timeout)
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	return client.Evaluate(ctx, call)
}

func applyAuditMode(result *harness.EvaluationResult, mode string) *harness.EvaluationResult {
	if mode != "audit" {
		return result
	}

	if result.Decision == harness.DecisionDeny || result.Decision == harness.DecisionAsk {
		return &harness.EvaluationResult{
			Decision:   harness.DecisionAllow,
			Reason:     fmt.Sprintf("[AUDIT-MODE: %s] %s", result.Decision, result.Reason),
			Source:     result.Source,
			Confidence: result.Confidence,
		}
	}

	return result
}

func outputHarnessVerdict(harnessType harness.HarnessType, result harness.EvaluationResult) int {
	exitCode, output, err := harness.FormatResponse(harnessType, result)
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

func handleFatalError(harnessType harness.HarnessType, msg string, err error) int {
	res := harness.EvaluationResult{
		Decision: harness.DecisionAsk,
		Reason:   fmt.Sprintf("%s: %v", msg, err),
		Source:   "fatal_error",
	}
	return outputHarnessVerdict(harnessType, res)
}
