package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"jev-guard/pkg/config"
	"jev-guard/pkg/harness"
)

// literalTargetTree builds a workspace with a benign readme.md and an outside directory holding
// a dummy key and a dummy plain file.
func literalTargetTree(t *testing.T) (ws, key, plain string) {
	t.Helper()
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ws = filepath.Join(base, "ws")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{filepath.Join(ws, ".git"), filepath.Join(ws, "d"), filepath.Join(outside, ".ssh")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	key = filepath.Join(outside, ".ssh", "id_rsa")
	plain = filepath.Join(outside, "notes.txt")
	for p, body := range map[string]string{
		key:                                   "DUMMY KEY",
		plain:                                 "dummy outside",
		filepath.Join(ws, "readme.md"):        "ok",
		filepath.Join(ws, "d", "readme.md"):   "ok",
		filepath.Join(ws, "plain.txt"):        "ok",
		filepath.Join(ws, "%2eenv"):           "literal name",
		filepath.Join(ws, "sub", "readme.md"): "",
	} {
		_ = os.MkdirAll(filepath.Dir(p), 0o700)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return ws, key, plain
}

func gateDecisionForPayload(t *testing.T, payload map[string]interface{}) (*harness.NormalizedToolCall, *gateTrace) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	call, err := harness.ParsePayload(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return call, traceGateEvaluation(call, config.DefaultConfig(), true)
}

// A read tool must be checked on the name it opens. Names that differ from the benign file
// only by surrounding whitespace, or (on POSIX) by a backslash, are separate entries that may
// be symlinks out of the workspace.
func TestReadTargetIsCheckedAsGiven(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("whitespace-suffixed and backslash names are POSIX file names")
	}
	ws, key, plain := literalTargetTree(t)
	names := []string{"readme.md\u0085", "readme.md\u00a0", " readme.md", "readme.md ", `d\readme.md`}
	for i, dest := range []string{key, plain} {
		dir := filepath.Join(ws, []string{"to-key", "to-plain"}[i])
		if err := os.MkdirAll(filepath.Join(dir, "d"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "readme.md"), []byte("ok"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "d", "readme.md"), []byte("ok"), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, name := range names {
			if err := os.Symlink(dest, filepath.Join(dir, name)); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
		}
		for _, name := range append([]string{}, names...) {
			for _, target := range []string{filepath.Join(dir, name), name} {
				t.Run(filepath.Base(dest)+"/"+strings.ReplaceAll(target, dir, "<abs>"), func(t *testing.T) {
					call, trace := gateDecisionForPayload(t, map[string]interface{}{
						"hook_event_name": "PreToolUse", "session_id": "s1", "cwd": dir,
						"tool_name": "Read", "tool_input": map[string]interface{}{"file_path": target},
					})
					if call.TargetPath != target {
						t.Fatalf("TargetPath = %q, want the raw argument %q", call.TargetPath, target)
					}
					if trace.Contained {
						t.Fatalf("target %q resolving outside the workspace was reported contained", target)
					}
					if trace.Final == nil || trace.Final.Decision != harness.DecisionAsk {
						t.Fatalf("target %q: final = %+v, want ASK", target, trace.Final)
					}
				})
			}
		}
		// Controls: the benign names are still allowed.
		for _, target := range []string{filepath.Join(dir, "readme.md"), "d/readme.md"} {
			_, trace := gateDecisionForPayload(t, map[string]interface{}{
				"hook_event_name": "PreToolUse", "session_id": "s1", "cwd": dir,
				"tool_name": "Read", "tool_input": map[string]interface{}{"file_path": target},
			})
			if trace.Final == nil || trace.Final.Decision != harness.DecisionAllow {
				t.Fatalf("control %q: final = %+v, want ALLOW", target, trace.Final)
			}
		}
	}
}

func fileURI(p string) string {
	p = filepath.ToSlash(p)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p // Windows drive path
	}
	return "file://" + p
}

// A file:// resource is checked on the path it names after URI parsing: the localhost
// authority and percent-encoding are decoded, and anything that does not map to one local
// path is asked about.
func TestReadResourceFileURIIsParsed(t *testing.T) {
	ws, key, plain := literalTargetTree(t)
	wsURI := fileURI(ws)
	cases := []struct {
		name, uri string
		want      harness.Decision
		contained bool
	}{
		{"localhost authority outside", "file://localhost" + strings.TrimPrefix(fileURI(plain), "file://"), harness.DecisionAsk, false},
		{"LOCALHOST authority outside key", "file://LOCALHOST" + strings.TrimPrefix(fileURI(key), "file://"), harness.DecisionAsk, false},
		{"encoded dot-dot", wsURI + "/%2e%2e/outside/notes.txt", harness.DecisionAsk, false},
		{"encoded dotenv", wsURI + "/%2eenv", harness.DecisionAsk, true},
		{"encoded ssh key", wsURI + "/%2e%2e/outside/%2essh/id%5frsa", harness.DecisionAsk, false},
		{"other host", "file://otherhost" + strings.TrimPrefix(wsURI, "file://") + "/plain.txt", harness.DecisionAsk, false},
		{"port", "file://localhost:8080" + strings.TrimPrefix(wsURI, "file://") + "/plain.txt", harness.DecisionAsk, false},
		{"user info", "file://user@localhost" + strings.TrimPrefix(wsURI, "file://") + "/plain.txt", harness.DecisionAsk, false},
		{"bad escape", wsURI + "/%zz", harness.DecisionAsk, false},
		{"encoded NUL", wsURI + "/plain.txt%00", harness.DecisionAsk, false},
		{"query", wsURI + "/plain.txt?x=1", harness.DecisionAsk, false},
		{"fragment", wsURI + "/plain.txt#x", harness.DecisionAsk, false},
		{"empty path", "file://", harness.DecisionAsk, false},
		{"control plain", wsURI + "/plain.txt", harness.DecisionAllow, true},
		{"control localhost plain", "file://localhost" + strings.TrimPrefix(wsURI, "file://") + "/plain.txt", harness.DecisionAllow, true},
		{"control encoded dot", wsURI + "/sub/readme%2Emd", harness.DecisionAllow, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			call := &harness.NormalizedToolCall{
				Harness: harness.HarnessAntigravity, ToolName: "read_resource", TargetPath: tc.uri,
				Cwd: ws, WorkspaceRoots: []string{ws}, RawArgs: map[string]interface{}{"Uri": tc.uri},
			}
			trace := traceGateEvaluation(call, config.DefaultConfig(), true)
			if trace.Final == nil || trace.Final.Decision != tc.want {
				t.Fatalf("%s: final = %+v, want %s", tc.uri, trace.Final, tc.want)
			}
			if trace.Contained != tc.contained {
				t.Fatalf("%s: contained = %v, want %v", tc.uri, trace.Contained, tc.contained)
			}
		})
	}
}

// Percent-encoded surrounding whitespace in a file URI names a different entry, as literal
// whitespace does, and is not checked as the trimmed name.
func TestReadResourceEncodedWhitespaceIsUnverifiable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("whitespace-suffixed names are POSIX file names")
	}
	ws, _, _ := literalTargetTree(t)
	if err := os.WriteFile(filepath.Join(ws, ".env"), []byte("DUMMY=1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(ws, ".env"), filepath.Join(ws, "readme.md ")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	for _, uri := range []string{fileURI(ws) + "/readme.md%20", fileURI(ws) + "/readme.md%c2%a0"} {
		call := &harness.NormalizedToolCall{
			Harness: harness.HarnessAntigravity, ToolName: "read_resource", TargetPath: uri,
			Cwd: ws, WorkspaceRoots: []string{ws}, RawArgs: map[string]interface{}{"Uri": uri},
		}
		trace := traceGateEvaluation(call, config.DefaultConfig(), true)
		if trace.Final == nil || trace.Final.Decision != harness.DecisionAsk || trace.Contained {
			t.Fatalf("%s: final = %+v, contained = %v; want ASK, not contained", uri, trace.Final, trace.Contained)
		}
	}
}

// Targets that are not a single absolute or workspace path as given are never contained.
func TestUnverifiableTargetsAreNotContained(t *testing.T) {
	ws, _, _ := literalTargetTree(t)
	for _, tc := range []struct {
		name, tool, key, target string
	}{
		{"whitespace-only write target", "Write", "file_path", " "},
		{"NBSP-only write target", "Write", "file_path", " "},
		{"file URI without slashes", "read_resource", "Uri", "file:/etc/passwd"},
		{"drive-relative file URI", "read_resource", "Uri", "file:///a:foo"},
		{"web fetch with leading space", "WebFetch", "url", " https://example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, trace := gateDecisionForPayload(t, map[string]interface{}{
				"hook_event_name": "PreToolUse", "session_id": "s1", "cwd": ws,
				"tool_name": tc.tool, "tool_input": map[string]interface{}{tc.key: tc.target},
			})
			if trace.Contained {
				t.Fatalf("target %q reported contained", tc.target)
			}
			if trace.Final == nil || trace.Final.Decision == harness.DecisionAllow {
				t.Fatalf("target %q: final = %+v, want not ALLOW", tc.target, trace.Final)
			}
		})
	}
}
