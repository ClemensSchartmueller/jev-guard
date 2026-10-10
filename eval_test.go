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
	for _, args := range [][]string{{}, {"--tool", "Write"}, {"--cmd", "ls", "--payload", "x"}, {"--bogus"}} {
		if code, _, _ := runEvalForTest(t, args...); code == 0 {
			t.Errorf("args %v: expected non-zero exit", args)
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