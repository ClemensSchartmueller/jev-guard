package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	`cat ~/.jev$'\0'guard/state`,
	`cat ~/.jev$'\x00ignored'guard/state`,
	`cat ~/.jev$'\u0000'guard/state`,
	`cat ~/.jev*/state`,
	`cat ~/.{jev,x}guard/state`,
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

// Commands that reach a custom security directory, and apply_patch headers that target any
// security directory, are denied with the fast path on or off.
func TestTraceGateEvaluationDeniesCustomHomeAndPatchTargets(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "jevguard-home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JEV_GUARD_HOME", home)
	ws := filepath.Join(root, "ws")
	if err := os.MkdirAll(ws, 0o700); err != nil {
		t.Fatal(err)
	}
	patch := func(header string) map[string]interface{} {
		return map[string]interface{}{"input": "*** Begin Patch\n" + header + "\n*** End Patch\n"}
	}
	calls := map[string]*harness.NormalizedToolCall{
		"cat custom home":      {ToolName: "Bash", Command: "cat " + filepath.Join(home, "state"), Cwd: ws},
		"cat relative":         {ToolName: "Bash", Command: "cat ../jevguard-home/state", Cwd: ws},
		"exec list":            {ToolName: "exec_command", Cwd: ws, RawArgs: map[string]interface{}{"cmd": []interface{}{"rm", "-rf", home}}},
		"patch delete":         {ToolName: "apply_patch", Cwd: ws, RawArgs: patch("*** Delete File: " + filepath.Join(home, "state"))},
		"patch add":            {ToolName: "apply_patch", Cwd: ws, RawArgs: patch("*** Add File: " + filepath.Join(home, "config.json") + "\n+{}")},
		"patch update":         {ToolName: "apply_patch", Cwd: ws, RawArgs: patch("*** Update File: ../jevguard-home/trust.json")},
		"patch move":           {ToolName: "apply_patch", Cwd: ws, RawArgs: patch("*** Update File: a.txt\n*** Move to: " + filepath.Join(home, "state"))},
		"patch default home":   {ToolName: "apply_patch", Cwd: ws, RawArgs: patch("*** Delete File: ~/.jevguard/state")},
		"patch config in repo": {ToolName: "apply_patch", Cwd: ws, RawArgs: patch("*** Update File: .jevguard.json")},
	}
	for _, fastpathOn := range []bool{true, false} {
		cfg := withFastpath(config.DefaultConfig(), fastpathOn)
		for name, call := range calls {
			call.UserIntent = "update my jev-guard state"
			trace := traceGateEvaluation(call, cfg, true)
			if trace.Final == nil || trace.Final.Decision != harness.DecisionDeny || trace.Final.Source != "fastpath_tampering" || trace.FastpathRan {
				t.Errorf("fastpath=%t %s: trace=%+v final=%+v; want fastpath_tampering DENY", fastpathOn, name, trace, trace.Final)
			}
		}
		clean := &harness.NormalizedToolCall{ToolName: "apply_patch", Cwd: ws, WorkspaceRoots: []string{ws}, RawArgs: patch("*** Update File: src/main.go")}
		if trace := traceGateEvaluation(clean, cfg, true); trace.Tampering != nil || trace.TamperingLimit != nil {
			t.Errorf("fastpath=%t workspace patch: trace=%+v; want no anti-tampering verdict", fastpathOn, trace)
		}
	}
}

// Hostile nesting is stopped by the shell-reading budget: the call gets the limit floor in
// well under a second instead of running for minutes, with the fast path on or off.
func TestTraceGateEvaluationBoundsShellWork(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	ws := t.TempDir()
	nested := "x"
	for range 10 {
		nested = `bash -c "` + strings.ReplaceAll(strings.ReplaceAll(nested, `\`, `\\`), `"`, `\"`) + `"`
	}
	for _, fastpathOn := range []bool{true, false} {
		for name, command := range map[string]string{
			"eval repeat":    strings.Repeat("eval ", 2000),
			"bash -c repeat": strings.Repeat("bash -c ", 20_000),
		} {
			start := time.Now()
			final := traceGateEvaluation(&harness.NormalizedToolCall{ToolName: "Bash", Command: command, Cwd: ws}, withFastpath(config.DefaultConfig(), fastpathOn), true).Final
			if elapsed := time.Since(start); elapsed > 3*time.Second {
				t.Errorf("fastpath=%t %s: took %v", fastpathOn, name, elapsed)
			}
			if final == nil || decisionRank(final.Decision) < decisionRank(harness.DecisionAsk) {
				t.Errorf("fastpath=%t %s: final=%+v; want at least ASK", fastpathOn, name, final)
			}

			// With the transcript guard on, its own limit keeps its source.
			if !fastpathOn {
				res := fastpath.CheckTranscriptTampering(&harness.NormalizedToolCall{ToolName: "Bash", Command: command, Cwd: ws})
				if res == nil || res.Decision != harness.DecisionAsk || res.Source != "transcript_guard_limit" {
					t.Errorf("%s: transcript guard = %+v; want transcript_guard_limit ASK", name, res)
				}
			}
		}
		start := time.Now()
		trace := traceGateEvaluation(&harness.NormalizedToolCall{ToolName: "Bash", Command: nested, Cwd: ws}, withFastpath(config.DefaultConfig(), fastpathOn), true)
		if elapsed := time.Since(start); elapsed > 3*time.Second || trace.Tampering != nil {
			t.Errorf("fastpath=%t nested bash -c: took %v, tampering=%+v", fastpathOn, elapsed, trace.Tampering)
		}
	}
}

// A force_ask from a later stage outranks the anti-tampering limit's ASK floor.
func TestTraceGateEvaluationForceAskOutranksLimitFloor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"answers":{
			"is_workspace_contained":{"type":"noul","noul":0.95},
			"destructive_potential":{"type":"score","score":0.5,"confidence":0.95},
			"violation_category":{"type":"choice","choice":"catastrophic_deletion","confidence":0.95},
			"intent_alignment":{"type":"choice","choice":"explicitly_requested","confidence":0.95}
		}}`)
	}))
	defer server.Close()
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	cfg := withFastpath(config.DefaultConfig(), false)
	cfg.APIKey, cfg.BaseURL = "test-key", server.URL
	call := &harness.NormalizedToolCall{ToolName: "Bash", Command: "rm -rf build " + strings.Repeat("a", 2<<20), Cwd: t.TempDir(), UserIntent: "delete the build folder"}
	trace := traceGateEvaluation(call, cfg, false)
	if trace.TamperingLimit == nil || !trace.SemanticRan {
		t.Fatalf("trace=%+v; want the limit floor and the TypeSafe stage", trace)
	}
	if trace.Final == nil || trace.Final.Decision != harness.DecisionForceAsk || trace.Final.Source != "policy_jev_intent_catastrophic" {
		t.Fatalf("final=%+v; want the policy's force_ask, not the ASK floor", trace.Final)
	}
}

func TestEvalDeniesCustomHomeAndPatchTargets(t *testing.T) {
	for _, userConfig := range []string{`{"fastpath_enabled": true}`, `{"fastpath_enabled": false}`} {
		e := newEvalEnv(t, userConfig)
		ws := e.workspace()
		if err := os.MkdirAll(e.jevHome, 0o700); err != nil {
			t.Fatal(err)
		}
		rep := e.report("--cmd", "cat "+filepath.Join(e.jevHome, "state"), "--offline", "--cwd", ws)
		requireVerdict(t, rep, harness.DecisionDeny, "fastpath_tampering")
		for name, target := range map[string]string{"default": filepath.Join(e.root, ".jevguard", "state"), "custom": filepath.Join(e.jevHome, "state")} {
			payload := filepath.Join(e.root, "patch-"+name+".json")
			body := `{"tool_name":"apply_patch","tool_input":{"input":` + jsonString("*** Begin Patch\n*** Delete File: "+target+"\n*** End Patch") + `},"cwd":` + jsonString(ws) + `}`
			if err := os.WriteFile(payload, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			rep := e.report("--payload", payload, "--offline")
			requireVerdict(t, rep, harness.DecisionDeny, "fastpath_tampering")
			if !rep.TamperingDenied {
				t.Errorf("%s %s patch: tampering_denied=false", userConfig, name)
			}
		}
	}
}

// A command nested deeper than the shell reader goes gets the limit floor whether fastpath is
// on or off, and with the transcript guard on, instead of going to semantic judgment unfloored.
func TestTraceGateEvaluationEncodedNestingDepthIsFloored(t *testing.T) {
	e := newEvalEnv(t, `{"mode":"enforcing"}`)
	ws := e.workspace()
	encode := func(command string, layers int) string {
		for range layers {
			var b strings.Builder
			for i := 0; i < len(command); i++ {
				fmt.Fprintf(&b, `\x%02x`, command[i])
			}
			command = "bash -c $'" + b.String() + "'"
		}
		return command
	}
	for _, layers := range []int{4, 5} {
		for _, fastpathOn := range []bool{true, false} {
			for name, cfg := range map[string]*config.Config{
				"default":            withFastpath(config.DefaultConfig(), fastpathOn),
				"transcript guarded": withFastpath(transcriptOnConfig(), fastpathOn),
			} {
				for _, inner := range []string{`cat ~/.jev\guard/state`, `cat ~/.gemini/antigravity/brain/x/.system_generated/logs/transcript.jsonl`} {
					call := &harness.NormalizedToolCall{ToolName: "Bash", Command: encode(inner, layers), Cwd: ws}
					trace := traceGateEvaluation(call, cfg, true)
					if trace.Final == nil || decisionRank(trace.Final.Decision) < decisionRank(harness.DecisionAsk) {
						t.Errorf("%d layers, fastpath=%t, %s, %q: final=%+v; want at least ASK", layers, fastpathOn, name, inner, trace.Final)
					}
					if trace.Tampering == nil && trace.TamperingLimit == nil {
						t.Errorf("%d layers, fastpath=%t, %s, %q: no anti-tampering verdict or floor", layers, fastpathOn, name, inner)
					}
				}
			}
		}
	}
}

func TestHookConfigGateRequiresApproval(t *testing.T) {
	ws := t.TempDir()
	for _, enabled := range []bool{true, false} {
		cfg := config.DefaultConfig()
		cfg.FastpathEnabled = &enabled
		for _, call := range []*harness.NormalizedToolCall{
			{ToolName: "Write", TargetPath: ".claude/settings.json", Cwd: ws, UserIntent: "change my hooks"},
			{ToolName: "apply_patch", Cwd: ws, RawArgs: map[string]interface{}{"input": "*** Begin Patch\n*** Delete File: .codex/hooks.json\n*** End Patch"}},
			{ToolName: "Bash", Command: "echo {} > .agents/hooks.json", Cwd: ws},
		} {
			trace := traceGateEvaluation(call, cfg, true)
			if trace.Final == nil || trace.Final.Decision != harness.DecisionAsk || trace.Final.Source != fastpath.SourceHookConfig || trace.FastpathRan != enabled {
				t.Fatalf("enabled=%t call=%+v: trace=%+v", enabled, call, trace)
			}
		}
	}
}

func TestHookConfigJudgeDenyOutranksFloor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"answers":{
			"is_workspace_contained":{"type":"noul","noul":0.95},
			"destructive_potential":{"type":"score","score":0.5,"confidence":0.95},
			"violation_category":{"type":"choice","choice":"catastrophic_deletion","confidence":0.95},
			"intent_alignment":{"type":"choice","choice":"not_requested","confidence":0.95}
		}}`)
	}))
	defer server.Close()
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	cfg := withFastpath(config.DefaultConfig(), false)
	cfg.APIKey, cfg.BaseURL = "test-key", server.URL
	call := &harness.NormalizedToolCall{ToolName: "Bash", Command: "rm -rf ~; echo x > .claude/settings.json", Cwd: t.TempDir(), UserIntent: "delete the build folder"}
	trace := traceGateEvaluation(call, cfg, false)
	if trace.TamperingLimit == nil || !trace.SemanticRan {
		t.Fatalf("trace=%+v; want the hook-config ASK floor and the TypeSafe stage", trace)
	}
	if trace.Final == nil || trace.Final.Decision != harness.DecisionDeny {
		t.Fatalf("final=%+v; want the policy DENY to outrank the hook-config ASK floor", trace.Final)
	}
}

func TestGuardSelfInvocationGate(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	deny := []string{
		"ingest --session x --prompt hi", "end-turn --session x", "end_turn --session x",
		"clear-intent --all", "clear_intent --all", "cache clear", "init",
		"config trust", "config untrust",
	}
	ask := []string{"status", "eval --cmd pwd", "explain --cmd pwd", "doctor", "config show", "cache", "cache status", "", "unknown"}
	forms := []string{
		"jev-guard %s", "jev-guard.exe %s", "/usr/local/bin/jev-guard %s", "./bin/jev-guard %s",
		`"C:\Tools\jev-guard.exe" %s`, "FOO=bar jev-guard %s", "FOO=bar env BAR=baz jev-guard %s",
		"env -u FOO jev-guard %s", "command -- jev-guard %s", "command -p jev-guard %s", "exec jev-guard %s", "exec -a alias jev-guard %s",
		"sudo -u root -- jev-guard %s", "doas jev-guard %s", "true&&jev-guard %s",
		"false||jev-guard %s", "true;jev-guard %s", "echo x|jev-guard %s", "true\njev-guard %s",
		"sh -c 'jev-guard %s'", `bash -lc 'jev-guard %s'`, `cmd /c "jev-guard %s"`,
		`pwsh -Command "& jev-guard %s"`, "npx @clemensschartmueller/jev-guard %s",
		"npx --yes @clemensschartmueller/jev-guard@1.2.3 %s", "echo $(jev-guard %s)",
	}
	for _, enabled := range []bool{true, false} {
		cfg := config.DefaultConfig()
		cfg.FastpathEnabled = &enabled
		for _, class := range []struct {
			args     []string
			decision harness.Decision
		}{{deny, harness.DecisionDeny}, {ask, harness.DecisionAsk}} {
			for _, args := range class.args {
				for _, form := range forms {
					command := fmt.Sprintf(form, args)
					trace := traceGateEvaluation(&harness.NormalizedToolCall{ToolName: "Bash", Command: command}, cfg, true)
					if trace.Final == nil || trace.Final.Decision != class.decision || trace.Final.Source != fastpath.SourceSelfInvocation {
						t.Errorf("enabled=%t command=%q: final=%+v; want %s", enabled, command, trace.Final, class.decision)
					}
					if class.decision == harness.DecisionDeny && (trace.FastpathRan || trace.WouldSendToJudge) {
						t.Errorf("%q reached later stages", command)
					}
				}
			}
		}
	}
	for _, command := range []string{
		"echo jev-guard", "grep jev-guard README.md", "echo jev-guard ingest", "echo sh -c 'jev-guard ingest'", "grep bash README.md", "cat /usr/bin/jev-guard",
		"jev-guard --version", "jev-guard --help", "jev-guard version", "jev-guard help",
		"echo npx @clemensschartmueller/jev-guard ingest", "npx @clemensschartmueller/jev-guard-other ingest",
	} {
		if result := fastpath.CheckAntiTampering(&harness.NormalizedToolCall{ToolName: "Bash", Command: command}); result != nil {
			t.Errorf("negative control %q: %+v", command, result)
		}
	}
	// A later mutating invocation must dominate an earlier read invocation.
	result := fastpath.CheckAntiTampering(&harness.NormalizedToolCall{Command: "jev-guard status && jev-guard ingest --prompt hi"})
	if !fastpath.IsTamperingDenial(result) {
		t.Fatalf("mixed command: %+v", result)
	}
	// Literal argv from exec-style harnesses also identifies the executable.
	for _, args := range [][]string{{"/bin/jev-guard", "ingest"}, {"env", "FOO=x", "jev-guard.exe", "clear-intent", "--all"}} {
		result := fastpath.CheckAntiTampering(&harness.NormalizedToolCall{ToolName: "exec", RawArgs: map[string]interface{}{"command": args}})
		if !fastpath.IsTamperingDenial(result) {
			t.Errorf("argv %q: %+v", args, result)
		}
	}
}

func TestSelfInvocationAskFloorPreservesJudgeDeny(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"answers":{"is_workspace_contained":{"type":"noul","noul":0.95},"destructive_potential":{"type":"score","score":0.99,"confidence":0.99},"violation_category":{"type":"choice","choice":"catastrophic_deletion","confidence":0.99},"intent_alignment":{"type":"choice","choice":"not_requested","confidence":0.99}}}`)
	}))
	defer server.Close()
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	cfg := withFastpath(config.DefaultConfig(), false)
	cfg.APIKey, cfg.BaseURL = "test-key", server.URL
	trace := traceGateEvaluation(&harness.NormalizedToolCall{ToolName: "Bash", Command: "jev-guard status; rm -rf /", Cwd: t.TempDir()}, cfg, false)
	if !trace.SemanticRan || trace.Final == nil || trace.Final.Decision != harness.DecisionDeny {
		t.Fatalf("trace=%+v final=%+v", trace, trace.Final)
	}
}

func TestSelfInvocationHookConfigPriority(t *testing.T) {
	for _, tc := range []struct {
		command, source string
		decision        harness.Decision
	}{
		{"jev-guard init; echo x > .claude/settings.json", fastpath.SourceSelfInvocation, harness.DecisionDeny},
		{"jev-guard status; echo x > .claude/settings.json", fastpath.SourceHookConfig, harness.DecisionAsk},
	} {
		r := fastpath.CheckAntiTampering(&harness.NormalizedToolCall{ToolName: "Bash", Command: tc.command, Cwd: t.TempDir()})
		if r == nil || r.Source != tc.source || r.Decision != tc.decision {
			t.Errorf("%s: %+v", tc.command, r)
		}
	}
}
