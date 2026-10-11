package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jev-guard/pkg/config"
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
