package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
