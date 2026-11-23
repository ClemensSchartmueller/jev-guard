package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

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
	args := os.Args[1:]
	if len(args) == 1 && args[0] == cli.AntigravityHookFlag {
		os.Exit(runGate(harness.HarnessAntigravity, config.EnsureUserConfig))
	}
	if len(args) == 0 && !cli.DefaultIsTerminal() {
		os.Exit(runGate(harness.HarnessUnknown, config.EnsureUserConfig))
	}

	if err := config.EnsureUserConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "jev-guard: cannot initialize user config: %v\n", err)
		if len(args) > 0 {
			os.Exit(2)
		}
	}
	runner := cli.NewRunner(os.Stdout, os.Stderr, func() bool { return true })
	runner.Eval = runEval
	runner.Explain = runExplain
	_, exitCode := runner.EvaluateArgs(args)
	os.Exit(exitCode)
}

const (
	gateDeadline = 10 * time.Second
	maxHookInput = 8 << 20
)

// gateLoadConfig is a seam so tests can inject configuration; the user config path is
// deliberately not overridable through the environment.
var gateLoadConfig = config.LoadConfigForCall

// hookReply is written only by the caller of awaitHookReply. The worker never
// writes a verdict directly because a timeout can win while it is still running.
type hookReply struct {
	exitCode int
	output   []byte
}

func runGate(expectedHarness harness.HarnessType, initialize func() error) int {
	ctx, cancel := context.WithTimeout(context.Background(), gateDeadline)
	defer cancel()
	var protocol atomic.Value
	protocol.Store(expectedHarness)
	var postToolUse atomic.Bool
	failure := func(reason string) hookReply {
		if postToolUse.Load() {
			fmt.Fprintln(os.Stderr, "jev-guard:", reason)
			return hookReply{}
		}
		return formatHookReply(&harness.NormalizedToolCall{Harness: protocol.Load().(harness.HarnessType)}, harness.EvaluationResult{
			Decision: harness.DecisionAsk,
			Reason:   reason,
			Source:   "fatal_error",
		})
	}

	reply := awaitHookReply(ctx, failure, func() hookReply {
		input, err := readStandardInput(os.Stdin)
		if err != nil {
			return failure("Failed to read standard input: " + err.Error())
		}

		// Dispatch a legacy PostToolUse hook from its envelope before parsing
		// tool arguments. The explicit Antigravity entry point is PreToolUse.
		if expectedHarness == harness.HarnessUnknown {
			if post := parsePostToolUseEnvelope(input); post != nil {
				postToolUse.Store(true)
				if err := initialize(); err != nil {
					fmt.Fprintf(os.Stderr, "jev-guard: cannot initialize user config: %v\n", err)
				}
				var output bytes.Buffer
				code := runPostToolUse(post, loadHookConfig(post), &output, os.Stderr)
				return hookReply{exitCode: code, output: output.Bytes()}
			}
		}

		call, err := harness.ParsePayload(input)
		if err != nil {
			return failure("Failed to parse tool call payload: " + err.Error())
		}
		if expectedHarness != harness.HarnessUnknown && call.Harness != expectedHarness {
			return failure("Unexpected hook payload format")
		}
		protocol.Store(call.Harness)
		if err := initialize(); err != nil {
			return failure("Cannot initialize user config: " + err.Error())
		}
		return evaluateHook(ctx, call)
	})

	if reply.exitCode == 2 {
		fmt.Fprintln(os.Stderr, string(reply.output))
	} else if len(reply.output) > 0 {
		if _, err := os.Stdout.Write(reply.output); err != nil {
			fmt.Fprintf(os.Stderr, "jev-guard: cannot write hook response: %v\n", err)
			return 2
		}
	}
	return reply.exitCode
}

func awaitHookReply(ctx context.Context, failure func(string) hookReply, work func() hookReply) hookReply {
	done := make(chan hookReply, 1)
	go func() {
		defer func() {
			if recover() != nil {
				done <- failure("jev-guard hook encountered an internal error")
			}
		}()
		done <- work()
	}()
	select {
	case reply := <-done:
		if ctx.Err() == nil {
			return reply
		}
	case <-ctx.Done():
	}
	return failure("jev-guard hook exceeded its evaluation deadline")
}

func loadHookConfig(call *harness.NormalizedToolCall) *config.Config {
	cfg := gateLoadConfig(call)
	for _, diagnostic := range cfg.Diagnostics {
		fmt.Fprintf(os.Stderr, "jev-guard: %s\n", diagnostic)
	}
	return cfg
}

func evaluateHook(ctx context.Context, call *harness.NormalizedToolCall) hookReply {
	cfg := loadHookConfig(call)
	defer boundary.BeginEvaluation()()

	if hold := gateHold(call, cfg, os.Stderr); hold != nil {
		if auditErr := cfg.LogAudit(call, hold); auditErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to write audit entry: %v\n", auditErr)
		}
		return formatHookReply(call, *applyAuditMode(hold, cfg.Mode))
	}

	trace := traceGateEvaluationWithContext(ctx, call, cfg, false)
	result := trace.Final
	if result.TaintNote != "" {
		fmt.Fprintf(os.Stderr, "jev-guard: taint %s\n", result.TaintNote)
	}
	if auditErr := cfg.LogAuditWithModel(call, result, trace.JudgedModel()); auditErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to write audit entry: %v\n", auditErr)
	}
	return formatHookReply(call, *result)
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
// to a hold the user could approve. Its ASK for limits, read-only self-invocation, or hook-config changes is not a
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

func readStandardInput(input io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(input, maxHookInput+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxHookInput {
		return nil, fmt.Errorf("hook payload exceeds %d bytes", maxHookInput)
	}
	return data, nil
}

// gateTrace records the intermediate results of the gate pipeline so that both the
// hook path and `jev-guard eval --explain` share a single implementation.
type gateTrace struct {
	Tampering        *harness.EvaluationResult // an anti-tampering DENY that decided the call
	TamperingLimit   *harness.EvaluationResult // anti-tampering's ASK floor for limits, read-only self-invocation, or hook-config changes
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
// (unless anti-tampering supplies a verdict or sets an ASK floor).
func traceGateEvaluation(call *harness.NormalizedToolCall, cfg *config.Config, offline bool) *gateTrace {
	return traceGateEvaluationWithContext(context.Background(), call, cfg, offline)
}

func traceGateEvaluationWithContext(ctx context.Context, call *harness.NormalizedToolCall, cfg *config.Config, offline bool) *gateTrace {
	defer boundary.BeginEvaluation()() // joins the scope of runGate or eval when there is one
	// Anti-tampering is a hard invariant, independent of fastpath_enabled and intent.
	tampering := fastpath.CheckAntiTampering(call)
	if fastpath.IsTamperingDenial(tampering) {
		return &gateTrace{Tampering: tampering, Final: applyAuditMode(tampering, cfg.Mode)}
	}
	if tampering == nil {
		return traceGateStages(ctx, call, cfg, offline, cfg.Mode)
	}
	// Non-denial anti-tampering results are floors, including limits and hook-config changes:
	// the later stages still run, so a DENY from them stands, and nothing weaker than ASK does.
	trace := traceGateStages(ctx, call, cfg, offline, "")
	trace.TamperingLimit = tampering
	if trace.Final == nil || (decisionRank(trace.Final.Decision) < decisionRank(tampering.Decision) || trace.Final.Decision == tampering.Decision && tampering.Source == fastpath.SourceHookConfig) {
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
func traceGateStages(ctx context.Context, call *harness.NormalizedToolCall, cfg *config.Config, offline bool, mode string) *gateTrace {
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
	trace.Judgments, trace.EvalErr = performSemanticEvaluation(ctx, call, cfg)

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
	// Surrounding whitespace makes the target unverifiable (fastpath.LocalTargetPaths), never a
	// URL that skips the boundary check.
	if target != strings.TrimSpace(target) {
		return false
	}
	lower := strings.ToLower(target)
	return strings.Contains(lower, "://") && !strings.HasPrefix(lower, "file://")
}

func checkWorkspaceBoundary(call *harness.NormalizedToolCall, checker fastpath.BoundaryChecker) bool {
	if call.TargetPath == "" {
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
	// Check every path the tool may open, as the fast path does: a file URI is decoded, and a
	// target that cannot be tied to one local path is never contained.
	targets, ok := fastpath.LocalTargetPaths(call.TargetPath)
	if !ok {
		return false
	}
	for _, target := range targets {
		contained, err := checker.IsPathContained(target, call.Cwd)
		if err != nil || !contained {
			return false
		}
	}
	return true
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
	scope := newPathScope(call)
	return harness.HasSingleTargetArg(call, key) && !scope.isExecutionSensitive(target) && pathProofResolvable(target, scope.cwd)
}

// pathProofResolvable withholds proof when an existing path component cannot
// be resolved. CanonicalizePath falls back to lexical paths for dangling links;
// a Write could follow such a link into configuration when creating its target.
// Missing ordinary files remain eligible if their nearest existing parent resolves.
func pathProofResolvable(target, cwd string) bool {
	if !filepath.IsAbs(target) {
		target = filepath.Join(cwd, target)
	}
	for {
		if _, err := os.Lstat(target); err == nil {
			_, err = filepath.EvalSymlinks(target)
			return err == nil
		} else if !os.IsNotExist(err) {
			return false
		}
		parent := filepath.Dir(target)
		if parent == target {
			return false
		}
		target = parent
	}
}

func performSemanticEvaluation(ctx context.Context, call *harness.NormalizedToolCall, cfg *config.Config) (*evaluator.JevJudgments, error) {
	client := evaluator.NewClient(cfg.APIKey, cfg.BaseURL, cfg.Model, cfg.Timeout)
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
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

func formatHookReply(call *harness.NormalizedToolCall, result harness.EvaluationResult) hookReply {
	exitCode, output, err := harness.FormatResponseForCall(call, result)
	if err != nil {
		if call.Harness == harness.HarnessAntigravity {
			return hookReply{output: []byte("{\"decision\":\"force_ask\",\"reason\":\"Failed to format hook response\"}\n")}
		}
		return hookReply{exitCode: 2, output: []byte("Failed to format hook response")}
	}
	if exitCode == 0 {
		output = append(output, '\n')
	}
	return hookReply{exitCode: exitCode, output: output}
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
