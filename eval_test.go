package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jev-guard/pkg/config"
	"jev-guard/pkg/harness"
)

func runEvalForTest(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("TYPESAFE_API_KEY", "")
	var out, errb bytes.Buffer
	code := runEval(args, strings.NewReader(""), &out, &errb)
	return code, out.String(), errb.String()
}

func TestEvalSensitiveCommandOffline(t *testing.T) {
	ws := t.TempDir()
	code, out, _ := runEvalForTest(t, "--cmd", "cat .env", "--offline", "--cwd="+ws)
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(strings.ToLower(out), "ask") || !strings.Contains(out, "fastpath") {
		t.Errorf("expected sensitive ask from fastpath, got %q", out)
	}
}

func TestEvalBoundaryEscapeOffline(t *testing.T) {
	ws := t.TempDir()
	outside := filepath.Join(t.TempDir(), "x.txt")
	code, out, _ := runEvalForTest(t, "--tool", "Write", "--target", outside, "--offline", "--cwd", ws)
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(strings.ToLower(out), "workspace") && !strings.Contains(strings.ToLower(out), "boundary") {
		t.Errorf("expected boundary escape, got %q", out)
	}
}

func TestEvalCodexPayloadFile(t *testing.T) {
	ws := t.TempDir()
	payload := `{"tool_name":"Bash","tool_input":{"command":"cat .env"},"cwd":` + jsonString(ws) + `,"session_id":"codex-1","hook_event_name":"PreToolUse"}`
	file := filepath.Join(t.TempDir(), "payload.json")
	if err := os.WriteFile(file, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runEvalForTest(t, "--payload="+file, "--offline")
	if code != 0 || !strings.Contains(strings.ToLower(out), "ask") {
		t.Errorf("code=%d out=%q", code, out)
	}
}

func TestEvalExplainShowsStages(t *testing.T) {
	ws := t.TempDir()
	code, out, _ := runEvalForTest(t, "--cmd", "cat .env", "--offline", "--explain", "--cwd", ws)
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	for _, stage := range []string{"Config", "Normalized tool call", "Boundary", "Fastpath", "TypeSafe", "Decision", "Harness output", "Hook exit code"} {
		if !strings.Contains(out, stage) {
			t.Errorf("explain output missing stage %q:\n%s", stage, out)
		}
	}
}

func TestEvalJSONParses(t *testing.T) {
	ws := t.TempDir()
	code, out, _ := runEvalForTest(t, "--cmd", "cat .env", "--offline", "--json", "--cwd", ws)
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	var rep map[string]interface{}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if rep["decision"] == nil || rep["tool_name"] != "Bash" {
		t.Errorf("unexpected report: %v", rep)
	}
}

func TestEvalUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{}, {"--tool", "Write"}, {"--cmd", "ls", "--payload", "x"}, {"--bogus"},
		{"--cmd", "--offline", "--json"}, {"--cmd", "ls", "--cwd", "--offline"},
		{"--tool", "Write", "--target", "--offline"}, {"--payload", "--offline"},
		{"--tool", "--offline", "--target", "x"}, {"--cmd=", "--payload=x"},
		{"--cmd", "ls", "--offline=invalid"}, {"--cmd", "ls", "--json="},
		{"--cmd", "ls", "--explain=nope"},
	} {
		if code, out, _ := runEvalForTest(t, args...); code != 2 || out != "" {
			t.Errorf("args %v: expected usage exit 2 and empty stdout, got %d, %q", args, code, out)
		}
	}
}

func TestEvalBooleanFlagValues(t *testing.T) {
	for _, flag := range []string{"--offline", "--explain", "--json"} {
		for _, value := range []string{"true", "false"} {
			o, err := parseEvalArgs([]string{"--cmd=git status", flag + "=" + value})
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]bool{"--offline": o.offline, "--explain": o.explain, "--json": o.asJSON}[flag]
			if got != (value == "true") {
				t.Errorf("%s=%s parsed as %t", flag, value, got)
			}
		}
	}
	// Explicit assignment still supports literal values beginning with --.
	if o, err := parseEvalArgs([]string{"--cmd=--offline"}); err != nil || o.cmd != "--offline" {
		t.Fatalf("explicit command value: options=%v err=%v", o, err)
	}
}

func TestEvalReportsAppliedProjectConfig(t *testing.T) {
	home, ws := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("TYPESAFE_API_KEY", "eval-secret-never-print")
	projectPath := filepath.Join(ws, ".jevguard.json")
	if err := os.WriteFile(projectPath, []byte(`{"sensitive_files":["private.data"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := config.InspectProjectConfig(projectPath)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := json.Marshal(map[string]interface{}{
		"version": 1, "entries": []config.ProjectConfigTrust{info.TrustRecord},
	})
	if err != nil {
		t.Fatal(err)
	}
	registryPath := config.TrustRegistryPath()
	if err := os.MkdirAll(filepath.Dir(registryPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(registryPath, registry, 0600); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"--explain", "--json"} {
		var out, errb bytes.Buffer
		code := runEval([]string{"--tool", "view_file", "--target", "private.data", "--cwd", ws, "--offline", format}, strings.NewReader(""), &out, &errb)
		if code != 0 || errb.Len() != 0 {
			t.Fatalf("%s: code=%d stderr=%q", format, code, errb.String())
		}
		if strings.Contains(out.String(), "eval-secret-never-print") {
			t.Fatal("report exposed credentials")
		}
		if format == "--json" {
			var rep evalReport
			if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
				t.Fatal(err)
			}
			if rep.ProjectConfigPath != info.ConfigPath || !rep.ProjectConfigTrusted || rep.Source != "fastpath_sensitive" || !strings.Contains(rep.SensitiveFilesSource, "trusted project config") {
				t.Fatalf("applied project config missing from report: %+v", rep)
			}
		} else {
			for _, want := range []string{info.ConfigPath, "trusted: true, applied", "trusted project config", "private.data"} {
				if !strings.Contains(out.String(), want) {
					t.Errorf("explanation missing %q: %s", want, out.String())
				}
			}
		}
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func runEvalWithConfig(t *testing.T, cfgJSON string, args ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(cfgJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := evalLoadConfig
	evalLoadConfig = func(call *harness.NormalizedToolCall) *config.Config {
		return config.LoadConfigWithPaths(nil, path, filepath.Join(t.TempDir(), "trust.json"))
	}
	t.Cleanup(func() { evalLoadConfig = orig })
	var out, errb bytes.Buffer
	if code := runEval(args, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("exit code = %d: %s", code, errb.String())
	}
	return out.String()
}

func TestEvalIntentDefersSensitiveToTypeSafe(t *testing.T) {
	ws := t.TempDir()
	_, withIntent, _ := runEvalForTest(t, "--cmd", "cat .env", "--intent", "show me the .env file", "--offline", "--cwd", ws)
	if !strings.Contains(withIntent, "would be sent to TypeSafe") {
		t.Errorf("expected deferral to TypeSafe, got %q", withIntent)
	}
	_, eq, _ := runEvalForTest(t, "--cmd", "cat .env", "--intent=show me the .env file", "--offline", "--cwd", ws)
	if eq != withIntent {
		t.Errorf("--intent=TEXT differs: %q vs %q", eq, withIntent)
	}
	_, without, _ := runEvalForTest(t, "--cmd", "cat .env", "--offline", "--cwd", ws)
	if strings.Contains(without, "would be sent to TypeSafe") || !strings.Contains(strings.ToLower(without), "ask") {
		t.Errorf("expected fastpath sensitive ask without intent, got %q", without)
	}
}

func TestEvalIntentExplainAndJSON(t *testing.T) {
	ws := t.TempDir()
	_, out, _ := runEvalForTest(t, "--cmd", "cat .env", "--intent", "show me the .env file", "--offline", "--explain", "--cwd", ws)
	if !strings.Contains(out, "Intent") || !strings.Contains(out, "show me the .env file") {
		t.Errorf("explain missing intent stage:\n%s", out)
	}
	_, js, _ := runEvalForTest(t, "--cmd", "cat .env", "--intent", "show me the .env file", "--offline", "--json", "--cwd", ws)
	var rep map[string]interface{}
	if err := json.Unmarshal([]byte(js), &rep); err != nil {
		t.Fatal(err)
	}
	if rep["intent"] != "show me the .env file" || rep["intent_applied"] != true {
		t.Errorf("unexpected intent fields: %v", rep)
	}
}

func TestEvalIntentAbortMirrorsHook(t *testing.T) {
	ws := t.TempDir()
	_, js, _ := runEvalForTest(t, "--cmd", "ls", "--intent", "stop", "--offline", "--json", "--cwd", ws)
	var rep map[string]interface{}
	if err := json.Unmarshal([]byte(js), &rep); err != nil {
		t.Fatal(err)
	}
	want := abortedSessionResult()
	if rep["decision"] != string(want.Decision) || rep["source"] != want.Source || rep["reason"] != want.Reason {
		t.Errorf("abort result differs from hook's: %v", rep)
	}
}

func TestEvalIntentIgnoredWhenContextAwarenessDisabled(t *testing.T) {
	ws := t.TempDir()
	cfg := `{"context_awareness_enabled": false}`
	out := runEvalWithConfig(t, cfg, "--cmd", "cat .env", "--intent", "show me the .env file", "--offline", "--json", "--cwd", ws)
	var rep map[string]interface{}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if rep["intent_applied"] != false || rep["would_send_to_typesafe"] != false || rep["fastpath_decision"] == nil {
		t.Errorf("intent should be ignored: %v", rep)
	}
	out = runEvalWithConfig(t, cfg, "--cmd", "ls", "--intent", "stop", "--offline", "--explain", "--cwd", ws)
	if strings.Contains(out, "session_aborted") || !strings.Contains(out, "context_awareness_enabled is false") {
		t.Errorf("abort intent should be ignored with a reason:\n%s", out)
	}
}

func TestEvalIntentUsageErrors(t *testing.T) {
	for _, suffix := range [][]string{
		{"--intent"},
		{"--intent", "--offline", "--json"},
		{"--intent", ""},
		{"--intent", "   "},
		{"--intent="},
		{"--intent=   "},
	} {
		args := append([]string{"--cmd", "cat .env"}, suffix...)
		t.Run(strings.Join(suffix, " "), func(t *testing.T) {
			code, out, errOut := runEvalForTest(t, args...)
			if code != 2 || out != "" || !strings.Contains(errOut, "--intent") {
				t.Fatalf("expected intent usage error: code=%d stdout=%q stderr=%q", code, out, errOut)
			}
		})
	}
}

func TestEvalIntentAbortReportsSkippedBoundary(t *testing.T) {
	ws := t.TempDir()
	for _, mode := range []string{"enforcing", "audit"} {
		t.Run(mode, func(t *testing.T) {
			out := runEvalWithConfig(t, `{"mode":"`+mode+`"}`, "--tool", "Write", "--target", filepath.Join(ws, "inside.txt"), "--cwd", ws, "--intent", "stop", "--offline", "--json")
			var rep map[string]interface{}
			if err := json.Unmarshal([]byte(out), &rep); err != nil {
				t.Fatal(err)
			}
			contained, present := rep["boundary_contained"]
			if !present || contained != nil {
				t.Fatalf("aborted boundary should be explicitly null: %s", out)
			}
			want := applyAuditMode(abortedSessionResult(), mode)
			if rep["decision"] != string(want.Decision) || rep["source"] != want.Source || rep["reason"] != want.Reason {
				t.Fatalf("abort result differs from hook: %s", out)
			}
			for _, field := range []string{"fastpath_ran", "typesafe_ran", "would_send_to_typesafe"} {
				if rep[field] != false {
					t.Errorf("%s should be false after abort: %s", field, out)
				}
			}
		})
	}
}

func TestEvalJSONBoundaryContainment(t *testing.T) {
	ws := t.TempDir()
	for _, tc := range []struct {
		name, target string
		contained    bool
	}{
		{"inside", filepath.Join(ws, "inside.txt"), true},
		{"outside", filepath.Join(t.TempDir(), "outside.txt"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errOut := runEvalForTest(t, "--tool", "Read", "--target", tc.target, "--cwd", ws, "--offline", "--json")
			if code != 0 {
				t.Fatalf("code=%d stderr=%s", code, errOut)
			}
			var rep evalReport
			if err := json.Unmarshal([]byte(out), &rep); err != nil {
				t.Fatal(err)
			}
			if rep.Contained == nil || *rep.Contained != tc.contained {
				t.Fatalf("incorrect containment report: %s", out)
			}
		})
	}
}
