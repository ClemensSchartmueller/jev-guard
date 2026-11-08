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
	initErr := config.EnsureUserConfig()
	if initErr != nil {
		fmt.Fprintf(os.Stderr, "jev-guard: cannot initialize user config: %v\n", initErr)
		// The gate decides after reading stdin: a PostToolUse event must still exit 0.
		if len(os.Args) > 1 {
			os.Exit(2)
		}
	}
	runner := cli.NewRunner(os.Stdout, os.Stderr, cli.DefaultIsTerminal)
	runner.Eval = runEval
	runner.Explain = runExplain
	action, exitCode := runner.EvaluateArgs(os.Args[1:])
	if action == cli.ActionHandled {
		os.Exit(exitCode)
	}

	exitCode = runGate(initErr)
	os.Exit(exitCode)
}

// gateLoadConfig is a seam so tests can inject configuration; the user config path is
// deliberately not overridable through the environment.
var gateLoadConfig = config.LoadConfigForCall

// runGate orchestrates ingestion, local fast-path, semantic evaluation, and response delivery.
// initErr is a user config initialization failure, which holds PreToolUse calls.
func runGate(initErr error) int {
	inputBytes, err := readStandardInput()
	if err != nil {
		return handleFatalError(nil, "Failed to read standard input", err)
	}

	// A PostToolUse payload reports a tool that already ran; it must never be
	// gated or answered as a pending PreToolUse call. It is dispatched from
	// its envelope, before the tool arguments are parsed.
	if post := parsePostToolUseEnvelope(inputBytes); post != nil {
		cfg := gateLoadConfig(post)
		for _, diagnostic := range cfg.Diagnostics {
			fmt.Fprintf(os.Stderr, "jev-guard: %s\n", diagnostic)
		}
		return runPostToolUse(post, cfg, os.Stdout, os.Stderr)
	}
	if initErr != nil {
		return 2
	}

	call, err := harness.ParsePayload(inputBytes)
	if err != nil {
		return handleFatalError(nil, "Failed to parse tool call payload", err)
	}

	cfg := gateLoadConfig(call)
	for _, diagnostic := range cfg.Diagnostics {
		fmt.Fprintf(os.Stderr, "jev-guard: %s\n", diagnostic)
	}

	// One path resolution budget for every check of this call (see boundary.BeginEvaluation).
	defer boundary.BeginEvaluation()()

	if hold := gateHold(call, cfg, os.Stderr); hold != nil {
		if auditErr := cfg.LogAudit(call, hold); auditErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to write audit entry: %v\n", auditErr)
		}
		return outputHarnessVerdict(call, *applyAuditMode(hold, cfg.Mode))
	}

	trace := traceGateEvaluation(call, cfg, false)
	result := trace.Final
	if result.TaintNote != "" {
		fmt.Fprintf(os.Stderr, "jev-guard: taint %s\n", result.TaintNote)
	}

	if auditErr := cfg.LogAuditWithModel(call, result, trace.JudgedModel()); auditErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to write audit entry: %v\n", auditErr)
	}

	return outputHarnessVerdict(call, *result)
}

// Session hold sources reported when context awareness stops a tool call
// before evaluation.
const (
	sourceSessionAborted   = "session_aborted"
	sourceSessionReadError = "session_read_error"
)

// applySessionContext resolves the user's prompt intent for the call when context
// awareness is enabled. It returns a force_ask hold when the session recorded an
// abort (regardless of turn: a successful ingest of a new prompt already clears it,
// so a mismatch only means that ingest failed), when the session state cannot be read
// or decoded (an unreadable session might be an aborted one, so it fails closed), or
// when the latest Antigravity transcript request is a stop command. Otherwise it sets
// call.UserIntent from the turn-matched session prompt and the transcript, copies the
// session's taint (if any) into call.Taint, and returns nil. An absent or expired session is not an error. The hold is returned before
// audit-mode rewriting.
func applySessionContext(call *harness.NormalizedToolCall, cfg *config.Config, stderr io.Writer) *harness.EvaluationResult {
	if !cfg.IsContextAwarenessEnabled() {
		return nil
	}
	session.SetSessionTTL(cfg.IntentTTL())
	sessionID := call.SessionID
	if sessionID == "" {
		sessionID = "default"
	}
	sessState, err := session.LoadSession(sessionID)
	if err != nil {
		fmt.Fprintf(stderr, "jev-guard: cannot read session state for '%s' (%s): %v\n", sessionID, session.SessionFilePath(sessionID), err)
		return &harness.EvaluationResult{
			Decision:   harness.DecisionForceAsk,
			Reason:     fmt.Sprintf("Action held: session state could not be read, so a recorded abort/stop signal cannot be ruled out: %v", err),
			Source:     sourceSessionReadError,
			Confidence: 1.0,
		}
	}
	if sessState != nil {
		if sessState.Aborted {
			return abortedSessionResult()
		}
		if call.TurnUnusable || sessState.TurnUnusable {
			// Neither side can prove which turn the prompt belongs to.
		} else if intent := resolveUserIntent(call.TurnID, sessState.TurnID, call.TurnKey, sessState.TurnKey, sessState.Prompt); intent != "" {
			call.UserIntent = intent
		}
		if sessState.Tainted && cfg.EffectiveTaintMode() != config.TaintModeOff {
			taint := session.TaintSource{ToolName: "unknown tool"}
			if sessState.TaintSource != nil {
				taint = *sessState.TaintSource
			}
			call.Taint = &taint
		}
	}
	// An empty home fails transcript path validation, which leaves the call unchanged.
	home, _ := os.UserHomeDir()
	if applyTranscriptIntent(call, cfg, home, stderr) {
		return abortedSessionResult()
	}
	return nil
}

// gateHold returns a verdict that stops the call before the gate runs. Anti-tampering
// comes first: its DENY is stronger than any session hold and must not be downgraded
// to a hold the user could approve. Its ASK for a command too large to check is not a
// hold: traceGateEvaluation applies it as a floor.
func gateHold(call *harness.NormalizedToolCall, cfg *config.Config, stderr io.Writer) *harness.EvaluationResult {
	if tampering := fastpath.CheckAntiTampering(call); fastpath.IsTamperingDenial(tampering) {
		return tampering
	}
	return applySessionContext(call, cfg, stderr)
}

// abortedSessionResult is the verdict the hook returns while an abort/stop signal is active.
func abortedSessionResult() *harness.EvaluationResult {
	return &harness.EvaluationResult{
		Decision:   harness.DecisionForceAsk,
		Reason:     "Action held: an active abort/stop signal was recorded for this session",
		Source:     sourceSessionAborted,
		Confidence: 1.0,
	}
}

// applyTranscriptIntent reads the latest user request from the Antigravity transcript when
// the harness and the antigravity_transcript_intent setting allow it.
// It sets call.UserIntent and returns false normally, or returns true when that request
// is a stop/abort command. An unusable latest user message or a redirected transcript location
// clears any session-cache intent already on the call, because the newest user message is
// authoritative and older intent must never be used as a fallback. Other errors (e.g.
// transcript unavailable) leave the call unchanged.
func applyTranscriptIntent(call *harness.NormalizedToolCall, cfg *config.Config, home string, stderr io.Writer) bool {
	if call.Harness != harness.HarnessAntigravity || !cfg.IsAntigravityTranscriptIntentEnabled() {
		return false
	}
	text, err := transcript.LatestUserInput(call.TranscriptPath, call.SessionID, home)
	if err != nil {
		if errors.Is(err, transcript.ErrUnusableUserInput) || errors.Is(err, transcript.ErrUntrustedLocation) {
			// The newest user message is authoritative; never fall back to older intent.
			call.UserIntent = ""
		}
		if !errors.Is(err, transcript.ErrNoUserInput) {
			fmt.Fprintf(stderr, "jev-guard: antigravity transcript intent unavailable: %v\n", err)
		}
		return false
	}
	if session.IsNegativeIntent(text) {
		// A hold carries no intent, even one a turn-matched session prompt supplied.
		call.UserIntent = ""
		return true
	}
	call.UserIntent = text
	return false
}

func readStandardInput() ([]byte, error) {
	return io.ReadAll(os.Stdin)
}

// gateTrace records the intermediate results of the gate pipeline so that both the
// hook path and `jev-guard eval --explain` share a single implementation.
type gateTrace struct {
	Tampering        *harness.EvaluationResult // an anti-tampering DENY, which decided the call
	TamperingLimit   *harness.EvaluationResult // anti-tampering's ASK floor for a command too large to check
	FastpathRan      bool
	Fastpath         *harness.EvaluationResult
	BoundaryRan      bool
	Contained        bool
	SemanticRan      bool
	Judgments        *evaluator.JevJudgments
	EvalErr          error
	WouldSendToJudge bool
	Final            *harness.EvaluationResult
}

// JudgedModel returns the semantic model that answered, or "" when no
// semantic response was received.
func (t *gateTrace) JudgedModel() string {
	if t == nil || t.Judgments == nil {
		return ""
	}
	return t.Judgments.Model
}

type boundaryResult struct {
	contained bool
	err       error
}

// cachedBoundaryChecker shares path resolution between the trace and fastpath
// for one evaluation. Distinct targets (including URI forms) stay independent.
type cachedBoundaryChecker struct {
	checker fastpath.BoundaryChecker
	results map[[2]string]boundaryResult
}

func (c *cachedBoundaryChecker) IsPathContained(target, cwd string) (bool, error) {
	key := [2]string{target, cwd}
	if result, ok := c.results[key]; ok {
		return result.contained, result.err
	}
	contained, err := c.checker.IsPathContained(target, cwd)
	if c.results == nil {
		c.results = make(map[[2]string]boundaryResult)
	}
	c.results[key] = boundaryResult{contained: contained, err: err}
	return contained, err
}

// traceGateEvaluation runs anti-tampering, boundary, fastpath, semantic evaluation, and policy.
// When offline is true the TypeSafe call is skipped and Final is nil if fastpath had no verdict
// (unless the anti-tampering limit set a floor).
func traceGateEvaluation(call *harness.NormalizedToolCall, cfg *config.Config, offline bool) *gateTrace {
	defer boundary.BeginEvaluation()() // joins the scope of runGate or eval when there is one
	// Anti-tampering is a hard invariant, independent of fastpath_enabled and intent.
	tampering := fastpath.CheckAntiTampering(call)
	if fastpath.IsTamperingDenial(tampering) {
		return &gateTrace{Tampering: tampering, Final: applyAuditMode(tampering, cfg.Mode)}
	}
	if tampering == nil {
		return traceGateStages(call, cfg, offline, cfg.Mode)
	}
	// The command was too large for anti-tampering to read. Its ASK is a floor, not a verdict:
	// the later stages still run, so a DENY from them stands, and nothing weaker than ASK does.
	trace := traceGateStages(call, cfg, offline, "")
	trace.TamperingLimit = tampering
	if trace.Final == nil || decisionRank(trace.Final.Decision) < decisionRank(tampering.Decision) {
		floor := *tampering
		if trace.Final != nil {
			floor.TaintNote = trace.Final.TaintNote
		}
		trace.Final = &floor
	}
	trace.Final = applyAuditMode(trace.Final, cfg.Mode)
	return trace
}

// decisionRank orders decisions from least to most restrictive.
func decisionRank(d harness.Decision) int {
	switch d {
	case harness.DecisionAsk:
		return 1
	case harness.DecisionForceAsk:
		return 2
	case harness.DecisionDeny:
		return 3
	}
	return 0
}

// traceGateStages runs the stages after anti-tampering. mode is the audit mode applied to
// the final verdict.
func traceGateStages(call *harness.NormalizedToolCall, cfg *config.Config, offline bool, mode string) *gateTrace {
	trace := &gateTrace{}
	resolver, _ := boundary.NewResolver(call.WorkspaceRoots, call.Cwd)
	var checker fastpath.BoundaryChecker
	if resolver != nil {
		checker = &cachedBoundaryChecker{checker: resolver}
	}
	trace.BoundaryRan = true
	trace.Contained = checkWorkspaceBoundary(call, checker)

	if cfg.IsFastpathEnabled() {
		trace.FastpathRan = true
		fastFilter := fastpath.NewFilter(checker, cfg)
		if fastResult := fastFilter.Evaluate(call); fastResult != nil {
			trace.Fastpath = fastResult
			trace.Final = applyAuditMode(applyTaint(call, fastResult, cfg, sensitiveChecker(cfg)), mode)
			return trace
		}
	} else if cfg.IsAntigravityTranscriptIntentEnabled() {
		// With the opt-in on, the transcript is an authorization input whether or not the fast path runs.
		if result := fastpath.CheckTranscriptTampering(call); result != nil {
			trace.Final = applyAuditMode(result, mode)
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
	resolved := pol.ResolveWithEvidence(trace.Judgments, policy.BoundaryEvidence{
		Contained:    trace.Contained,
		PathVerified: isLocalPathVerified(call, trace.Contained),
		Egress:       policy.IsEgressCall(call),
	}, trace.EvalErr)
	trace.Final = applyAuditMode(applyTaint(call, resolved, cfg, sensitiveChecker(cfg)), mode)
	return trace
}

// isNetworkURL reports whether target has a URL scheme other than file://.
func isNetworkURL(target string) bool {
	lower := strings.ToLower(strings.TrimSpace(target))
	return strings.Contains(lower, "://") && !strings.HasPrefix(lower, "file://")
}

func checkWorkspaceBoundary(call *harness.NormalizedToolCall, checker fastpath.BoundaryChecker) bool {
	if strings.TrimSpace(call.TargetPath) == "" {
		return true
	}
	// A fetch tool's target is a network URL, not a local path, so there is nothing to
	// contain. Resolving it as a path fails on Windows (`?` is not a valid name character)
	// and would turn every WebFetch into a boundary escape. Only outbound tools get this:
	// any other tool's "x://../.." target is still resolved, because the OS reads it as a
	// relative path.
	if policy.IsOutboundTool(call.ToolName) && isNetworkURL(call.TargetPath) {
		return true
	}
	if checker == nil {
		return false
	}
	contained, err := checker.IsPathContained(call.TargetPath, call.Cwd)
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
	return harness.HasSingleTargetArg(call, key) && !isExecutionSensitivePath(target)
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
			TaintNote:  result.TaintNote,
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

func resolveUserIntent(callTurnID, sessionTurnID int, callTurnKey, sessionTurnKey, sessionPrompt string) string {
	if callTurnKey != "" || sessionTurnKey != "" {
		// A string key on either side requires the same key on both. Keyed sessions
		// normally store numeric turn 0, which the numeric rule below would accept for any call.
		if sessionTurnKey != callTurnKey {
			return ""
		}
		return sessionPrompt
	}
	if callTurnID == 0 || sessionTurnID == 0 || callTurnID == sessionTurnID {
		return sessionPrompt
	}
	return ""
}
