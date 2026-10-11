package main

import (
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"jev-guard/pkg/config"
	"jev-guard/pkg/harness"
	"jev-guard/pkg/session"
)

// TestMain makes the production config loader unusable in this package's tests: every test
// that runs eval must go through newEvalEnv, which injects temp paths. Without this, a test
// would read (and the trust-registry helpers would write) the real ~/.jevguard, because
// config paths come from the OS account (user.Current), not from $HOME.
func TestMain(m *testing.M) {
	evalLoadConfig = func(*harness.NormalizedToolCall) *config.Config {
		panic("eval test ran without newEvalEnv: it would read the real user configuration")
	}
	os.Exit(m.Run())
}

// evalEnv is an isolated configuration, trust registry, session and audit environment.
type evalEnv struct {
	t                                *testing.T
	root, userConfig, trust, jevHome string
}

func newEvalEnv(t *testing.T, userConfigJSON string) *evalEnv {
	t.Helper()
	root := t.TempDir()
	e := &evalEnv{
		t:          t,
		root:       root,
		userConfig: filepath.Join(root, "user", ".jevguard.json"),
		trust:      filepath.Join(root, "user", "trusted-project-configs.json"),
		jevHome:    filepath.Join(root, "jevguard-home"),
	}
	if err := os.MkdirAll(filepath.Dir(e.userConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	if userConfigJSON != "" {
		if err := os.WriteFile(e.userConfig, []byte(userConfigJSON), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("TYPESAFE_API_KEY", "")
	orig := evalLoadConfig
	t.Cleanup(func() { evalLoadConfig = orig })
	e.activate()
	return e
}

// activate points the environment variables and the config seam at this env. It runs before
// every eval so several envs can coexist in one test.
func (e *evalEnv) activate() {
	e.t.Setenv("HOME", e.root)
	e.t.Setenv("USERPROFILE", e.root)
	e.t.Setenv("JEV_GUARD_HOME", e.jevHome)
	evalLoadConfig = func(call *harness.NormalizedToolCall) *config.Config {
		cfg := config.LoadConfigForCallWithPaths(call, e.userConfig, e.trust)
		e.requireIsolated("user config", cfg.UserConfigPath)
		e.requireIsolated("session directory", session.GetSessionsDir())
		if cfg.AuditLogPath != "" {
			audit := cfg.AuditLogPath
			if !filepath.IsAbs(audit) {
				audit = filepath.Join(call.Cwd, audit)
			}
			e.requireIsolated("audit log", audit)
		}
		return cfg
	}
}

// requireIsolated fails the test if a resolved path is outside this test's temp root,
// which also rules out anything under the real user home.
func (e *evalEnv) requireIsolated(what, path string) {
	e.t.Helper()
	rel, err := filepath.Rel(e.root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		e.t.Fatalf("%s resolved outside the isolated test root %s: %s", what, e.root, path)
	}
}

// workspace returns a fresh workspace directory inside the isolated root.
func (e *evalEnv) workspace() string {
	e.t.Helper()
	dir, err := os.MkdirTemp(e.root, "ws-")
	if err != nil {
		e.t.Fatal(err)
	}
	return dir
}

func (e *evalEnv) run(args ...string) (int, string, string) {
	return e.runCmd(runEval, args...)
}

func (e *evalEnv) runCmd(cmd func([]string, io.Reader, io.Writer, io.Writer) int, args ...string) (int, string, string) {
	e.activate()
	var out, errb bytes.Buffer
	code := cmd(args, strings.NewReader(""), &out, &errb)
	return code, out.String(), errb.String()
}

func (e *evalEnv) mustRun(args ...string) string {
	e.t.Helper()
	code, out, errOut := e.run(args...)
	if code != 0 || errOut != "" {
		e.t.Fatalf("eval %v: code=%d stderr=%q", args, code, errOut)
	}
	return out
}

func (e *evalEnv) report(args ...string) evalReport {
	e.t.Helper()
	out := e.mustRun(append(args, "--json")...)
	var rep evalReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		e.t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	return rep
}

func (e *evalEnv) rawReport(args ...string) map[string]interface{} {
	e.t.Helper()
	out := e.mustRun(append(args, "--json")...)
	var rep map[string]interface{}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		e.t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	return rep
}

func requireVerdict(t *testing.T, rep evalReport, decision harness.Decision, source string) {
	t.Helper()
	if rep.Decision != string(decision) || rep.Source != source {
		t.Fatalf("verdict = %q/%q, want %q/%q (reason: %s)", rep.Decision, rep.Source, decision, source, rep.Reason)
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestEvalSensitiveCommandOffline(t *testing.T) {
	e := newEvalEnv(t, "")
	rep := e.report("--cmd", "cat .env", "--offline", "--cwd="+e.workspace())
	requireVerdict(t, rep, harness.DecisionAsk, "fastpath_sensitive")
}

func TestEvalSensitivePayloadSources(t *testing.T) {
	e := newEvalEnv(t, "")
	ws := e.workspace()
	for name, payload := range map[string]string{
		"codex bash":       `{"tool_name":"Bash","tool_input":{"command":"cat .env"},"cwd":` + jsonString(ws) + `,"session_id":"codex-1","hook_event_name":"PreToolUse"}`,
		"claude read":      `{"tool_name":"Read","tool_input":{"file_path":` + jsonString(filepath.Join(ws, ".env")) + `},"cwd":` + jsonString(ws) + `}`,
		"antigravity view": `{"toolCall":{"name":"view_file","args":{"AbsolutePath":` + jsonString(filepath.Join(ws, "id_rsa")) + `}},"workspacePaths":[` + jsonString(ws) + `]}`,
	} {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(e.root, strings.ReplaceAll(name, " ", "-")+".json")
			if err := os.WriteFile(file, []byte(payload), 0o600); err != nil {
				t.Fatal(err)
			}
			requireVerdict(t, e.report("--payload="+file, "--offline"), harness.DecisionAsk, "fastpath_sensitive")
		})
	}
}

func TestEvalBoundaryEscapeOffline(t *testing.T) {
	e := newEvalEnv(t, "")
	outside := filepath.Join(e.workspace(), "x.txt")
	rep := e.report("--tool", "Write", "--target", outside, "--offline", "--cwd", e.workspace())
	requireVerdict(t, rep, harness.DecisionAsk, "fastpath_boundary")
	if rep.BoundaryStatus != boundaryStatusEscaped || rep.Contained == nil || *rep.Contained {
		t.Fatalf("boundary = %q/%v, want escaped/false", rep.BoundaryStatus, rep.Contained)
	}
}

func TestEvalSynthesizedToolUsesCanonicalPathArgument(t *testing.T) {
	for tool, key := range map[string]string{"write_to_file": "TargetFile", "view_file": "AbsolutePath", "NotebookEdit": "notebook_path", "Write": "file_path", "Glob": "path", "custom_tool": "file_path"} {
		raw, err := synthesizePayload(&evalOptions{tool: tool, target: "/w/a.txt"}, "/w")
		if err != nil {
			t.Fatal(err)
		}
		call, err := harness.ParsePayload(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := call.RawArgs[key].(string); got != "/w/a.txt" || len(call.RawArgs) != 1 {
			t.Errorf("%s: args = %v, want only %s", tool, call.RawArgs, key)
		}
	}
}

func TestEvalExplainShowsStages(t *testing.T) {
	e := newEvalEnv(t, "")
	ws := e.workspace()
	viaFlag := e.mustRun("--cmd", "cat .env", "--offline", "--explain", "--cwd", ws)
	for _, stage := range []string{"Config", "Normalized tool call", "Intent", "Boundary", "Fastpath", "TypeSafe", "Decision", "Harness output", "Hook exit code"} {
		if !strings.Contains(viaFlag, "] "+stage+"\n") {
			t.Errorf("explain output missing stage %q:\n%s", stage, viaFlag)
		}
	}
	code, viaCommand, errOut := e.runCmd(runExplain, "--cmd", "cat .env", "--offline", "--cwd", ws)
	if code != 0 || errOut != "" || viaCommand != viaFlag {
		t.Fatalf("explain command differs from eval --explain: code=%d stderr=%q\n%s", code, errOut, viaCommand)
	}
}

func TestExplainCommandRejectsOutputFlags(t *testing.T) {
	e := newEvalEnv(t, "")
	for _, flag := range []string{"--json", "--explain", "--explain=false"} {
		code, out, errOut := e.runCmd(runExplain, "--cmd", "ls", flag)
		if code != 2 || out != "" || !strings.HasPrefix(errOut, "jev-guard explain: usage error: explain always prints") {
			t.Errorf("%s: code=%d stdout=%q stderr=%q", flag, code, out, errOut)
		}
	}
}

func TestEvalJSONParses(t *testing.T) {
	e := newEvalEnv(t, "")
	rep := e.report("--cmd", "cat .env", "--offline", "--cwd", e.workspace())
	if rep.ToolName != "Bash" || rep.Command != "cat .env" || rep.BoundaryStatus != boundaryStatusNoTarget {
		t.Errorf("unexpected report: %+v", rep)
	}
}

func TestEvalUsageErrors(t *testing.T) {
	e := newEvalEnv(t, "")
	for _, tc := range []struct {
		args []string
		msg  string
	}{
		{nil, "specify exactly one of --cmd, --tool with --target, or --payload"},
		{[]string{"--tool", "Write"}, "--tool and --target must be used together"},
		{[]string{"--cmd", "ls", "--payload", "x"}, "specify exactly one of --cmd, --tool with --target, or --payload"},
		{[]string{"--bogus"}, "unrecognized argument --bogus"},
		{[]string{"--cmd", "ls", "extra"}, "unrecognized argument extra"},
		// A string flag never swallows the next option as its value.
		{[]string{"--cmd", "--offline", "--json"}, "flag --cmd requires a value"},
		{[]string{"--cmd", "ls", "--cwd", "--offline"}, "flag --cwd requires a value"},
		{[]string{"--tool", "Write", "--target", "--offline"}, "flag --target requires a value"},
		{[]string{"--payload", "--offline"}, "flag --payload requires a value"},
		{[]string{"--tool", "--offline", "--target", "x"}, "flag --tool requires a value"},
		{[]string{"--cmd", "ls", "--intent", "--json"}, "flag --intent requires a value"},
		{[]string{"--cmd", "ls", "--intent"}, "flag --intent requires a value"},
		{[]string{"--cmd="}, "flag --cmd requires a non-empty value"},
		{[]string{"--cmd", "ls", "--intent=  "}, "flag --intent requires a non-empty value"},
		// Booleans accept only explicit boolean values.
		{[]string{"--cmd", "ls", "--offline=invalid"}, "flag --offline requires a boolean value"},
		{[]string{"--cmd", "ls", "--json="}, "flag --json requires a boolean value"},
		{[]string{"--cmd", "ls", "--explain=nope"}, "flag --explain requires a boolean value"},
		{[]string{"--cmd", "ls", "--offline", "false"}, "unrecognized argument false"},
		// Repeated flags are rejected instead of silently keeping the last value.
		{[]string{"--cmd", "ls", "--cmd", "pwd"}, "flag --cmd given more than once"},
		{[]string{"--cmd", "ls", "--offline", "--offline=false"}, "flag --offline given more than once"},
	} {
		code, out, errOut := e.run(tc.args...)
		wantFirst := "jev-guard eval: usage error: " + tc.msg
		if code != 2 || out != "" || strings.SplitN(errOut, "\n", 2)[0] != wantFirst || !strings.Contains(errOut, "Usage: jev-guard eval") {
			t.Errorf("args %q: code=%d stdout=%q stderr=%q, want exit 2 and %q", tc.args, code, out, errOut, wantFirst)
		}
	}
}

func TestEvalFlagValues(t *testing.T) {
	for _, flag := range []string{"--offline", "--explain", "--json"} {
		for _, value := range []string{"true", "false", "1", "0"} {
			o, err := parseEvalArgs([]string{"--cmd=git status", flag + "=" + value})
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]bool{"--offline": o.offline, "--explain": o.explain, "--json": o.asJSON}[flag]
			if want := value == "true" || value == "1"; got != want {
				t.Errorf("%s=%s parsed as %t", flag, value, got)
			}
		}
	}
	// Explicit assignment is the documented way to pass literal values beginning with --.
	o, err := parseEvalArgs([]string{"--cmd=--offline", "--intent=--json", "--cwd=--dir", "--json=false"})
	if err != nil {
		t.Fatal(err)
	}
	if o.cmd != "--offline" || o.intent != "--json" || o.cwd != "--dir" || o.offline || o.asJSON {
		t.Fatalf("explicit values parsed as %+v", *o)
	}
	// Separate values may contain '=' and single dashes.
	if o, err := parseEvalArgs([]string{"--cmd", "env A=b -i"}); err != nil || o.cmd != "env A=b -i" {
		t.Fatalf("separate value: %+v %v", o, err)
	}
}

func TestEvalJSONFlagFalseEmitsSummary(t *testing.T) {
	e := newEvalEnv(t, "")
	out := e.mustRun("--cmd", "cat .env", "--offline", "--json=false", "--cwd", e.workspace())
	if strings.HasPrefix(strings.TrimSpace(out), "{") || !strings.HasPrefix(out, "ASK: ") || !strings.HasSuffix(out, "(source: fastpath_sensitive)\n") {
		t.Fatalf("--json=false should print the summary line, got %q", out)
	}
}

func TestEvalReportsAppliedProjectConfig(t *testing.T) {
	e := newEvalEnv(t, "")
	ws := e.workspace()
	t.Setenv("TYPESAFE_API_KEY", "eval-secret-never-print")
	projectPath := filepath.Join(ws, ".jevguard.json")
	if err := os.WriteFile(projectPath, []byte(`{"sensitive_files":["private.data"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := config.InspectProjectConfigWithRegistry(projectPath, e.trust)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := json.Marshal(map[string]interface{}{
		"version": 1, "entries": []config.ProjectConfigTrust{info.TrustRecord},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.trust, registry, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--tool", "view_file", "--target", "private.data", "--cwd", ws, "--offline"}

	rep := e.report(args...)
	requireVerdict(t, rep, harness.DecisionAsk, "fastpath_sensitive")
	if rep.ProjectConfigPath != info.ConfigPath || !rep.ProjectConfigTrusted || !strings.Contains(rep.SensitiveFilesSource, "trusted project config") {
		t.Fatalf("applied project config missing from report: %+v", rep)
	}
	explain := e.mustRun(append(args, "--explain")...)
	for _, want := range []string{info.ConfigPath, "trusted: true, applied", "trusted project config", "private.data"} {
		if !strings.Contains(explain, want) {
			t.Errorf("explanation missing %q: %s", want, explain)
		}
	}
	for _, out := range []string{explain, e.mustRun(append(args, "--json")...)} {
		if strings.Contains(out, "eval-secret-never-print") {
			t.Fatal("report exposed credentials")
		}
	}
}

func TestEvalIntentDefersSensitiveToTypeSafe(t *testing.T) {
	e := newEvalEnv(t, "")
	ws := e.workspace()
	with := e.report("--cmd", "cat .env", "--intent", "show me the .env file", "--offline", "--cwd", ws)
	if with.Decision != "" || !with.WouldSendToJudge || with.FastpathDecision != "" || !with.IntentApplied || with.Intent != "show me the .env file" {
		t.Errorf("expected deferral to TypeSafe, got %+v", with)
	}
	eq := e.report("--cmd", "cat .env", "--intent=show me the .env file", "--offline", "--cwd", ws)
	if eq.WouldSendToJudge != with.WouldSendToJudge || eq.Intent != with.Intent || eq.IntentApplied != with.IntentApplied {
		t.Errorf("--intent=TEXT differs: %+v vs %+v", eq, with)
	}
	requireVerdict(t, e.report("--cmd", "cat .env", "--offline", "--cwd", ws), harness.DecisionAsk, "fastpath_sensitive")
}

func TestEvalIntentExplain(t *testing.T) {
	e := newEvalEnv(t, "")
	out := e.mustRun("--cmd", "cat .env", "--intent", "show me the .env file", "--offline", "--explain", "--cwd", e.workspace())
	if !strings.Contains(out, "] Intent\n    \"show me the .env file\": set as the user intent for this call\n") {
		t.Errorf("explain missing intent stage:\n%s", out)
	}
}

func TestEvalIntentIgnoredWhenContextAwarenessDisabled(t *testing.T) {
	e := newEvalEnv(t, `{"context_awareness_enabled": false}`)
	ws := e.workspace()
	rep := e.report("--cmd", "cat .env", "--intent", "show me the .env file", "--offline", "--cwd", ws)
	requireVerdict(t, rep, harness.DecisionAsk, "fastpath_sensitive")
	if rep.IntentApplied || rep.WouldSendToJudge {
		t.Errorf("intent should be ignored: %+v", rep)
	}
	rep = e.report("--cmd", "ls", "--intent", "stop", "--offline", "--cwd", ws)
	requireVerdict(t, rep, harness.DecisionAllow, "fastpath_trusted")
	if rep.IntentApplied || rep.IntentNote != "ignored: context_awareness_enabled is false in config" {
		t.Errorf("abort intent should be ignored with a reason: %+v", rep)
	}
}

// TestEvalIntentAbort covers the explicit --intent stop path in enforcing and audit mode. The
// expected values are literals so a change to the hook's abort verdict is caught here too.
func TestEvalIntentAbort(t *testing.T) {
	const abortReason = "Action held: an active abort/stop signal was recorded for this session"
	for _, tc := range []struct {
		mode, decision, reason string
	}{
		{"enforcing", "force_ask", abortReason},
		{"audit", "allow", "[AUDIT-MODE: force_ask] " + abortReason},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			e := newEvalEnv(t, `{"mode":"`+tc.mode+`"}`)
			ws := e.workspace()
			for _, args := range [][]string{
				{"--cmd", "ls"},
				{"--tool", "Write", "--target", filepath.Join(ws, "inside.txt")},
				{"--tool", "Write", "--target", filepath.Join(e.workspace(), "outside.txt")},
			} {
				args = append(args, "--cwd", ws, "--intent", "stop", "--offline")
				raw := e.rawReport(args...)
				if raw["decision"] != tc.decision || raw["source"] != "session_aborted" || raw["reason"] != tc.reason || raw["mode"] != tc.mode {
					t.Fatalf("%v: abort verdict = %v", args, raw)
				}
				if contained, present := raw["boundary_contained"]; !present || contained != nil || raw["boundary_status"] != boundaryStatusSkipped {
					t.Fatalf("%v: skipped boundary must be status skipped and containment null: %v", args, raw)
				}
				for _, field := range []string{"fastpath_ran", "typesafe_ran", "would_send_to_typesafe"} {
					if raw[field] != false {
						t.Errorf("%v: %s should be false after abort: %v", args, field, raw)
					}
				}
				explain := e.mustRun(append(args, "--explain")...)
				if !strings.Contains(explain, "] Boundary\n    skipped (session aborted)\n") {
					t.Errorf("explain disagrees with JSON boundary_status:\n%s", explain)
				}
			}
		})
	}
}

func TestEvalJSONBoundaryStatus(t *testing.T) {
	e := newEvalEnv(t, "")
	ws := e.workspace()
	for _, tc := range []struct {
		name      string
		args      []string
		status    string
		contained bool
		explain   string
	}{
		{"inside", []string{"--tool", "Read", "--target", filepath.Join(ws, "inside.txt")}, boundaryStatusContained, true, "target is inside the workspace"},
		{"outside", []string{"--tool", "Read", "--target", filepath.Join(e.workspace(), "outside.txt")}, boundaryStatusEscaped, false, "target is OUTSIDE the workspace"},
		{"no target", []string{"--cmd", "ls"}, boundaryStatusNoTarget, true, "no target path: treated as contained"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append(tc.args, "--cwd", ws, "--offline")
			rep := e.report(args...)
			if rep.BoundaryStatus != tc.status || rep.Contained == nil || *rep.Contained != tc.contained {
				t.Fatalf("boundary = %q/%v, want %q/%t", rep.BoundaryStatus, rep.Contained, tc.status, tc.contained)
			}
			if explain := e.mustRun(append(args, "--explain")...); !strings.Contains(explain, "] Boundary\n    "+tc.explain) {
				t.Errorf("explain disagrees with JSON boundary_status %q:\n%s", tc.status, explain)
			}
		})
	}
}

// TestEvalAuditModeRewritesAsk verifies audit mode turns blocking verdicts into ALLOW with the
// documented "[AUDIT-MODE: <decision>] <reason>" reason while keeping the source.
func TestEvalAuditModeRewritesAsk(t *testing.T) {
	enforcing := newEvalEnv(t, `{"mode":"enforcing"}`)
	audit := newEvalEnv(t, `{"mode":"audit"}`)
	for _, args := range [][]string{
		{"--cmd", "cat .env"},
		{"--tool", "Write", "--target", filepath.Join(t.TempDir(), "outside.txt")},
	} {
		ws := t.TempDir()
		args = append(args, "--cwd", ws, "--offline")
		blocked := enforcing.report(args...)
		if blocked.Decision != string(harness.DecisionAsk) || blocked.Mode != "enforcing" {
			t.Fatalf("%v: enforcing verdict = %+v", args, blocked)
		}
		rewritten := audit.report(args...)
		requireVerdict(t, rewritten, harness.DecisionAllow, blocked.Source)
		if want := "[AUDIT-MODE: ask] " + blocked.Reason; rewritten.Reason != want || rewritten.Mode != "audit" {
			t.Errorf("%v: audit reason = %q, want %q", args, rewritten.Reason, want)
		}
	}
}

// snapshotTree records entry modes and file contents/modification times.
// Directory timestamps can update asynchronously on Windows after fixture setup.
func snapshotTree(t *testing.T, root string) map[string]string {
	t.Helper()
	snap := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) && path == root {
				return filepath.SkipDir
			}
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		entry := info.Mode().String()
		if !d.IsDir() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			entry += " " + info.ModTime().String() + " " + string(data)
		}
		snap[path] = entry
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func TestSnapshotTreeDetectsFileAndDirectoryChanges(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "config.json")
	if err := os.WriteFile(file, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := snapshotTree(t, root)
	changedTime := time.Now().Add(-time.Hour)
	if err := os.Chtimes(root, changedTime, changedTime); err != nil {
		t.Fatal(err)
	}
	if !equalSnapshots(before, snapshotTree(t, root)) {
		t.Fatal("directory timestamp change should not count as a write")
	}
	if err := os.Chtimes(file, changedTime, changedTime); err != nil {
		t.Fatal(err)
	}
	if equalSnapshots(before, snapshotTree(t, root)) {
		t.Fatal("file timestamp change was not detected")
	}
	before = snapshotTree(t, root)
	if err := os.WriteFile(file, []byte("modified"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(file, changedTime, changedTime); err != nil {
		t.Fatal(err)
	}
	if equalSnapshots(before, snapshotTree(t, root)) {
		t.Fatal("file content change with preserved timestamp was not detected")
	}
	before = snapshotTree(t, root)
	dir := filepath.Join(root, "audit")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	after := snapshotTree(t, root)
	if equalSnapshots(before, after) {
		t.Fatal("new directory was not detected")
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if equalSnapshots(after, snapshotTree(t, root)) {
		t.Fatal("removed directory was not detected")
	}
}

func TestEvalWritesNoAuditLog(t *testing.T) {
	for _, mode := range []string{"enforcing", "audit"} {
		t.Run(mode, func(t *testing.T) {
			e := newEvalEnv(t, "")
			absLog := filepath.Join(e.root, "audit", "jevguard.log")
			if err := os.WriteFile(e.userConfig, []byte(`{"mode":"`+mode+`","audit_log_path":`+jsonString(absLog)+`}`), 0o600); err != nil {
				t.Fatal(err)
			}
			ws := e.workspace()
			relLog := filepath.Join(ws, ".jevguard.log")
			before := snapshotTree(t, e.root)
			e.mustRun("--cmd", "cat .env", "--offline", "--cwd", ws)
			e.mustRun("--cmd", "ls", "--intent", "stop", "--offline", "--json", "--cwd", ws)
			e.mustRun("--tool", "Write", "--target", filepath.Join(ws, "a.txt"), "--offline", "--explain", "--cwd", ws)
			for _, p := range []string{absLog, filepath.Dir(absLog), relLog} {
				if _, err := os.Stat(p); !os.IsNotExist(err) {
					t.Errorf("eval created %s (err=%v)", p, err)
				}
			}
			if after := snapshotTree(t, e.root); !equalSnapshots(before, after) {
				t.Errorf("eval changed files in the isolated root:\nbefore=%v\nafter=%v", before, after)
			}
		})
	}
}

func equalSnapshots(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestEvalIgnoresAndPreservesSessionState(t *testing.T) {
	e := newEvalEnv(t, "")
	ws := e.workspace()
	// A cached positive intent for the payload's session and an aborted default session.
	for _, state := range []*session.SessionState{
		{SessionID: "codex-1", TurnID: 1, Prompt: "show me the .env file"},
		{SessionID: "default", TurnID: 1, Prompt: "stop"},
	} {
		if err := session.SaveSession(state); err != nil {
			t.Fatal(err)
		}
	}
	if aborted, err := session.LoadSession("default"); err != nil || aborted == nil || !aborted.Aborted {
		t.Fatalf("seeding the aborted session failed: %+v %v", aborted, err)
	}
	payload := filepath.Join(e.root, "payload.json")
	if err := os.WriteFile(payload, []byte(`{"tool_name":"Bash","tool_input":{"command":"cat .env"},"cwd":`+jsonString(ws)+`,"session_id":"codex-1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	before := snapshotTree(t, e.jevHome)

	// The cached intent would defer to TypeSafe; the cached abort would hold. Neither applies.
	rep := e.report("--payload", payload, "--offline")
	requireVerdict(t, rep, harness.DecisionAsk, "fastpath_sensitive")
	if rep.IntentApplied || rep.Intent != "" {
		t.Errorf("cached intent applied implicitly: %+v", rep)
	}
	requireVerdict(t, e.report("--cmd", "ls", "--offline", "--cwd", ws), harness.DecisionAllow, "fastpath_trusted")
	// An explicit --intent does not get persisted either.
	e.mustRun("--cmd", "ls", "--intent", "stop", "--offline", "--cwd", ws)
	e.mustRun("--cmd", "cat .env", "--intent", "read the env", "--offline", "--cwd", ws)

	if after := snapshotTree(t, e.jevHome); !equalSnapshots(before, after) || len(after) == 0 {
		t.Errorf("session files changed:\nbefore=%v\nafter=%v", before, after)
	}
}
