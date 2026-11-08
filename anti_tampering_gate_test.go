package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jev-guard/pkg/config"
	"jev-guard/pkg/fastpath"
	"jev-guard/pkg/harness"
	"jev-guard/pkg/session"
)

// escapedTamperingCommands spell ~/.jevguard so that its raw text does not contain the name.
var escapedTamperingCommands = []string{
	`cat ~/.jev\guard/state`,
	`cat ~/.jev"guard"/state`,
	`cat ~/.jev$'guard'/state`,
	`cat ~/.jev$'\x67'uard/state`,
	"Get-Content ~/.jev`guard/state",
	`bash -c 'cat ~/.jev\guard/state'`,
}

func TestTraceGateEvaluationDeniesEscapedTampering(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	ws := t.TempDir()
	calls := map[string]*harness.NormalizedToolCall{}
	for _, command := range escapedTamperingCommands {
		calls[command] = &harness.NormalizedToolCall{ToolName: "Bash", Command: command, Cwd: ws, UserIntent: "show me my jev-guard config"}
	}
	for _, glob := range []string{"*jevguard*.json", "**/.jev*", "*JevGuard*"} {
		calls["Grep glob "+glob] = &harness.NormalizedToolCall{ToolName: "Grep", TargetPath: ws, Cwd: ws,
			RawArgs: map[string]interface{}{"pattern": "api_key", "path": ws, "glob": glob}}
	}
	for _, fastpathOn := range []bool{true, false} {
		enabled := fastpathOn
		cfg := config.DefaultConfig()
		cfg.FastpathEnabled = &enabled
		for name, call := range calls {
			trace := traceGateEvaluation(call, cfg, true)
			if trace.Final == nil || trace.Final.Decision != harness.DecisionDeny || trace.Final.Source != "fastpath_tampering" {
				t.Errorf("fastpath=%t %s: final=%+v; want fastpath_tampering DENY", fastpathOn, name, trace.Final)
			}
			if trace.FastpathRan || trace.WouldSendToJudge {
				t.Errorf("fastpath=%t %s: anti-tampering must decide first, trace=%+v", fastpathOn, name, trace)
			}
		}
	}
}

func TestTraceGateEvaluationKeepsBroadFileFilters(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	ws := t.TempDir()
	cfg := config.DefaultConfig()
	for _, glob := range []string{"*.json", "**/*", "*"} {
		call := &harness.NormalizedToolCall{ToolName: "Grep", TargetPath: ws, Cwd: ws, WorkspaceRoots: []string{ws},
			RawArgs: map[string]interface{}{"pattern": "api_key", "path": ws, "glob": glob}}
		trace := traceGateEvaluation(call, cfg, true)
		if trace.Tampering != nil || trace.Final == nil || trace.Final.Decision != harness.DecisionAllow {
			t.Errorf("glob %q: tampering=%+v final=%+v; want fast-path ALLOW", glob, trace.Tampering, trace.Final)
		}
	}
}

func TestGateHoldEscapedTamperingAndLimit(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	if err := os.MkdirAll(session.GetSessionsDir(), 0700); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	var stderr bytes.Buffer
	for _, command := range escapedTamperingCommands {
		hold := gateHold(&harness.NormalizedToolCall{SessionID: "s1", ToolName: "Bash", Command: command}, cfg, &stderr)
		if !fastpath.IsTamperingDenial(hold) {
			t.Errorf("%s: hold=%+v; want DENY", command, hold)
		}
	}

	// The limit ASK is a floor applied by the gate, not a hold, so a session hold still decides.
	huge := "echo " + strings.Repeat("a", 2<<20)
	if hold := gateHold(&harness.NormalizedToolCall{SessionID: "s1", ToolName: "Bash", Command: huge}, cfg, &stderr); hold != nil {
		t.Fatalf("oversized command hold=%+v; want no hold", hold)
	}
	if err := session.SaveSession(&session.SessionState{SessionID: "s1", Prompt: "stop"}); err != nil {
		t.Fatal(err)
	}
	hold := gateHold(&harness.NormalizedToolCall{SessionID: "s1", ToolName: "Bash", Command: huge}, cfg, &stderr)
	if hold == nil || hold.Decision != harness.DecisionForceAsk {
		t.Fatalf("oversized command in aborted session hold=%+v; want the session hold", hold)
	}
}

// A command too large for anti-tampering to read gets at least ASK, but a stricter verdict from
// a later stage stands.
func TestTraceGateEvaluationAntiTamperingLimitIsAFloor(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	ws := t.TempDir()
	padding := strings.Repeat("a", 2<<20)
	for _, fastpathOn := range []bool{true, false} {
		enabled := fastpathOn
		cfg := config.DefaultConfig()
		cfg.FastpathEnabled = &enabled

		trace := traceGateEvaluation(&harness.NormalizedToolCall{ToolName: "Bash", Command: "echo " + padding, Cwd: ws}, cfg, true)
		if trace.Tampering != nil || trace.TamperingLimit == nil || trace.Final == nil ||
			trace.Final.Decision != harness.DecisionAsk || trace.Final.Source != fastpath.SourceAntiTamperingLimit {
			t.Errorf("fastpath=%t: trace=%+v final=%+v; want the limit ASK", fastpathOn, trace, trace.Final)
		}
		if trace.BoundaryRan != true || trace.FastpathRan != fastpathOn {
			t.Errorf("fastpath=%t: later stages must still run, trace=%+v", fastpathOn, trace)
		}

		// With the transcript guard on, its DENY for a transcript path is not lowered to ASK.
		guarded := withFastpath(transcriptOnConfig(), fastpathOn)
		final := traceGateEvaluation(&harness.NormalizedToolCall{ToolName: "Bash", Command: "cat ~/.gemini/antigravity/brain/x/.system_generated/logs/transcript.jsonl " + padding, Cwd: ws}, guarded, true).Final
		if final == nil || final.Decision != harness.DecisionDeny || final.Source != "fastpath_tampering" {
			t.Errorf("fastpath=%t: final=%+v; want the transcript guard's DENY", fastpathOn, final)
		}

		cfg.Mode = "audit"
		final = traceGateEvaluation(&harness.NormalizedToolCall{ToolName: "Bash", Command: "echo " + padding, Cwd: ws}, cfg, true).Final
		if final == nil || final.Decision != harness.DecisionAllow || final.Source != fastpath.SourceAntiTamperingLimit || !strings.HasPrefix(final.Reason, "[AUDIT-MODE: ask] ") {
			t.Errorf("fastpath=%t audit: final=%+v; want the audited limit ASK", fastpathOn, final)
		}
	}
}

func TestEvalDeniesEscapedTampering(t *testing.T) {
	for _, userConfig := range []string{`{"fastpath_enabled": true}`, `{"fastpath_enabled": false}`} {
		e := newEvalEnv(t, userConfig)
		ws := e.workspace()
		for _, command := range escapedTamperingCommands {
			rep := e.report("--cmd", command, "--offline", "--cwd", ws)
			requireVerdict(t, rep, harness.DecisionDeny, "fastpath_tampering")
			if !rep.TamperingDenied {
				t.Errorf("%s %s: tampering_denied=false", userConfig, command)
			}
		}
		payload := filepath.Join(e.root, "grep.json")
		body := `{"tool_name":"Grep","tool_input":{"pattern":"api_key","path":".","glob":"*jevguard*.json"},"cwd":` + jsonString(ws) + `}`
		if err := os.WriteFile(payload, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		rep := e.report("--payload", payload, "--offline")
		requireVerdict(t, rep, harness.DecisionDeny, "fastpath_tampering")
		if !rep.TamperingDenied {
			t.Errorf("%s: wildcard glob tampering_denied=false", userConfig)
		}
	}
}

func TestEvalAntiTamperingLimit(t *testing.T) {
	e := newEvalEnv(t, "")
	args := []string{"--cmd", "echo " + strings.Repeat("a", 2<<20), "--offline", "--cwd", e.workspace()}
	rep := e.report(args...)
	requireVerdict(t, rep, harness.DecisionAsk, fastpath.SourceAntiTamperingLimit)
	if rep.TamperingDenied || !rep.FastpathRan {
		t.Errorf("limit report=%+v; want no denial and the fast path still run", rep)
	}
	out := e.mustRun(append(args, "--explain")...)
	if !strings.Contains(out, "] Anti-tampering\n    floor: ask - ") {
		t.Errorf("explain does not show the limit floor:\n%.2000s", out)
	}
}
