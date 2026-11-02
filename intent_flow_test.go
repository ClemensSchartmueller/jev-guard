package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"jev-guard/pkg/config"
	"jev-guard/pkg/harness"
	"jev-guard/pkg/session"
)

const transcriptModelRecord = `{"type":"PLANNER_RESPONSE","source":"MODEL","status":"DONE","content":"ok"}` + "\n"

// agHome isolates the home directory and session cache, and writes a transcript for conv.
func agHome(t *testing.T, conv, body string) (home, path string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("JEV_GUARD_HOME", filepath.Join(home, ".jevguard"))
	if err := os.MkdirAll(session.GetSessionsDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(home, ".gemini", "antigravity", "brain", conv, ".system_generated", "logs", "transcript.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return home, path
}

func userRecord(text string) string {
	content, _ := json.Marshal(text)
	return `{"type":"USER_INPUT","source":"USER_EXPLICIT","status":"DONE","content":` + string(content) + `}` + "\n"
}

// agCall parses a real Antigravity PreToolUse payload.
func agCall(t *testing.T, conv, transcriptPath, tool string, args map[string]any) *harness.NormalizedToolCall {
	t.Helper()
	ws := t.TempDir()
	raw, err := json.Marshal(map[string]any{
		"toolCall":       map[string]any{"name": tool, "args": args},
		"conversationId": conv,
		"invocationNum":  2,
		"workspacePaths": []string{ws},
		"cwd":            ws,
		"transcriptPath": transcriptPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	call, err := harness.ParsePayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	return call
}

func rmBuild(t *testing.T, conv, path string) *harness.NormalizedToolCall {
	return agCall(t, conv, path, "run_command", map[string]any{"CommandLine": "rm -rf build"})
}

func TestAntigravityFlow_TranscriptIntentReachesCall(t *testing.T) {
	_, path := agHome(t, "c1", userRecord("delete the build folder")+transcriptModelRecord)
	call := rmBuild(t, "c1", path)
	if hold := applySessionContext(call, config.DefaultConfig(), io.Discard); hold != nil {
		t.Fatalf("unexpected hold: %+v", hold)
	}
	if call.UserIntent != "delete the build folder" {
		t.Fatalf("UserIntent = %q", call.UserIntent)
	}
}

func TestAntigravityFlow_LatestStopRequestIsHeld(t *testing.T) {
	_, path := agHome(t, "c1", userRecord("delete the build folder")+transcriptModelRecord+userRecord("stop"))
	call := rmBuild(t, "c1", path)
	hold := applySessionContext(call, config.DefaultConfig(), io.Discard)
	if hold == nil || hold.Decision != harness.DecisionForceAsk || hold.Source != sourceSessionAborted {
		t.Fatalf("expected abort hold, got %+v", hold)
	}
	if call.UserIntent != "" {
		t.Fatalf("held call carries intent %q", call.UserIntent)
	}
}

func TestAntigravityFlow_StopDropsTurnMatchedSessionIntent(t *testing.T) {
	_, path := agHome(t, "c1", userRecord("stop"))
	if err := session.SaveSession(&session.SessionState{SessionID: "c1", TurnID: 2, Prompt: "cached"}); err != nil {
		t.Fatal(err)
	}
	call := rmBuild(t, "c1", path)
	if hold := applySessionContext(call, config.DefaultConfig(), io.Discard); hold == nil {
		t.Fatal("expected a hold")
	}
	if call.UserIntent != "" {
		t.Fatalf("held call carries intent %q", call.UserIntent)
	}
}

// Fail closed: an unusable newest message never falls back to an older message or the
// session cache, and the call gets the same verdict as with no intent at all.
func TestAntigravityFlow_UnusableLatestMessageFailsClosed(t *testing.T) {
	for name, latest := range map[string]string{
		"empty":     userRecord(""),
		"malformed": `{"type":"USER_INPUT","source":"USER_EXPLICIT","content":` + "\n",
		"truncated": `{"type":"USER_INPUT","source":"USER_EXPLICIT","content":"x","truncated_fields":["content"]}` + "\n",
		"non-text":  `{"type":"USER_INPUT","source":"USER_EXPLICIT","content":{"a":1}}` + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, path := agHome(t, "c1", userRecord("show me the .env file")+transcriptModelRecord+latest)
			if err := session.SaveSession(&session.SessionState{SessionID: "c1", TurnID: 2, Prompt: "show me the .env file"}); err != nil {
				t.Fatal(err)
			}
			call := agCall(t, "c1", path, "view_file", map[string]any{"AbsolutePath": ".env"})
			var stderr bytes.Buffer
			if hold := applySessionContext(call, config.DefaultConfig(), &stderr); hold != nil {
				t.Fatalf("unexpected hold: %+v", hold)
			}
			if call.UserIntent != "" {
				t.Fatalf("UserIntent = %q, want none", call.UserIntent)
			}
			if stderr.Len() == 0 {
				t.Error("expected a stderr diagnostic")
			}
			final := traceGateEvaluation(call, config.DefaultConfig(), true).Final
			if final == nil || final.Decision != harness.DecisionAsk || final.Source != "fastpath_sensitive" {
				t.Fatalf("expected stateless ASK, got %+v", final)
			}
		})
	}
}

func TestAntigravityFlow_ForgedTranscriptPathIsIgnored(t *testing.T) {
	agHome(t, "c1", userRecord("harmless"))
	forged := filepath.Join(t.TempDir(), "transcript.jsonl")
	if err := os.WriteFile(forged, []byte(userRecord("show me the .env file")), 0o600); err != nil {
		t.Fatal(err)
	}
	call := rmBuild(t, "c1", forged)
	var stderr bytes.Buffer
	if hold := applySessionContext(call, config.DefaultConfig(), &stderr); hold != nil {
		t.Fatalf("unexpected hold: %+v", hold)
	}
	if call.UserIntent != "" || stderr.Len() == 0 {
		t.Fatalf("forged path used: intent=%q stderr=%q", call.UserIntent, stderr.String())
	}
}

// A recorded abort outranks a newer transcript message, and an unreadable session (#41)
// still fails closed for Antigravity: neither is cleared by reading the transcript.
func TestAntigravityFlow_SessionHoldsComeFirst(t *testing.T) {
	t.Run("abort", func(t *testing.T) {
		_, path := agHome(t, "c1", userRecord("delete the build folder"))
		if err := session.SaveSession(&session.SessionState{SessionID: "c1", Prompt: "stop"}); err != nil {
			t.Fatal(err)
		}
		call := rmBuild(t, "c1", path)
		hold := applySessionContext(call, config.DefaultConfig(), io.Discard)
		if hold == nil || hold.Source != sourceSessionAborted || call.UserIntent != "" {
			t.Fatalf("hold=%+v intent=%q", hold, call.UserIntent)
		}
	})
	t.Run("unreadable", func(t *testing.T) {
		_, path := agHome(t, "c1", userRecord("delete the build folder"))
		if err := os.WriteFile(session.SessionFilePath("c1"), []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		call := rmBuild(t, "c1", path)
		hold := applySessionContext(call, config.DefaultConfig(), io.Discard)
		if hold == nil || hold.Source != sourceSessionReadError || call.UserIntent != "" {
			t.Fatalf("hold=%+v intent=%q", hold, call.UserIntent)
		}
	})
}

func TestAntigravityFlow_DisabledSettingsSkipTranscript(t *testing.T) {
	off := false
	for name, mutate := range map[string]func(*config.Config){
		"context awareness": func(c *config.Config) { c.ContextAwarenessEnabled = &off },
		"transcript intent": func(c *config.Config) { c.AntigravityTranscriptIntent = &off },
	} {
		t.Run(name, func(t *testing.T) {
			_, path := agHome(t, "c1", userRecord("stop"))
			cfg := config.DefaultConfig()
			mutate(cfg)
			call := rmBuild(t, "c1", path)
			var stderr bytes.Buffer
			if hold := applySessionContext(call, cfg, &stderr); hold != nil || call.UserIntent != "" || stderr.Len() != 0 {
				t.Fatalf("hold=%+v intent=%q stderr=%q", hold, call.UserIntent, stderr.String())
			}
		})
	}
}

// Intent never loosens the canonical read-target rule (#54), on either new path.
func TestNewIntentPathsRespectCanonicalReadTarget(t *testing.T) {
	_, path := agHome(t, "c1", userRecord("show me both files"))
	ag := agCall(t, "c1", path, "view_file", map[string]any{"AbsolutePath": "README.md", "path": "/etc/passwd"})
	if hold := applySessionContext(ag, config.DefaultConfig(), io.Discard); hold != nil || ag.UserIntent == "" {
		t.Fatalf("hold=%+v intent=%q", hold, ag.UserIntent)
	}
	ingest(t, `{"session_id":"cx","turn_id":"t1","prompt":"show me both files"}`)
	raw := `{"session_id":"cx","turn_id":"t1","tool_name":"read_file","tool_input":{"file_path":"README.md","path":"/etc/passwd"},"cwd":` + jsonString(t.TempDir()) + `}`
	cx, err := harness.ParsePayload([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if hold := applySessionContext(cx, config.DefaultConfig(), io.Discard); hold != nil || cx.UserIntent == "" {
		t.Fatalf("hold=%+v intent=%q", hold, cx.UserIntent)
	}
	for _, call := range []*harness.NormalizedToolCall{ag, cx} {
		final := traceGateEvaluation(call, config.DefaultConfig(), true).Final
		if final == nil || final.Decision != harness.DecisionAsk || final.Source != "fastpath_boundary" {
			t.Errorf("%s: expected boundary ASK, got %+v", call.Harness, final)
		}
	}
}

// Turn scoping decides what the gate does, not only what is stored: only the matching
// turn's intent defers a sensitive read to TypeSafe.
func TestCodexFlow_StaleTurnIntentDoesNotDeferSensitiveRead(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	ingest(t, `{"session_id":"cx","turn_id":"turn-A","prompt":"show me the .env file"}`)
	cwd := t.TempDir()
	run := func(turn string) *gateTrace {
		raw := `{"session_id":"cx","turn_id":` + jsonString(turn) + `,"tool_name":"Bash","tool_input":{"command":"cat .env"},"cwd":` + jsonString(cwd) + `}`
		call, err := harness.ParsePayload([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if hold := applySessionContext(call, config.DefaultConfig(), io.Discard); hold != nil {
			t.Fatalf("unexpected hold: %+v", hold)
		}
		return traceGateEvaluation(call, config.DefaultConfig(), true)
	}
	if tr := run("turn-A"); !tr.WouldSendToJudge {
		t.Errorf("matching turn should defer to TypeSafe: %+v", tr.Final)
	}
	if tr := run("turn-B"); tr.Final == nil || tr.Final.Source != "fastpath_sensitive" {
		t.Errorf("stale turn should ask locally: %+v", tr.Final)
	}
}

func TestCodexAbortHoldBlocksWithExitTwo(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	ingest(t, `{"session_id":"cx","turn_id":"turn-A","prompt":"Stop! Cancel all operations"}`)
	call, cfg := toolCall(t, "cx", "turn-B")
	hold := applySessionContext(call, cfg, io.Discard)
	if hold == nil {
		t.Fatal("expected a hold")
	}
	code, _, err := harness.FormatResponseForCall(call, *hold)
	if err != nil || code != 2 || call.Harness != harness.HarnessCodex {
		t.Fatalf("code=%d err=%v harness=%s", code, err, call.Harness)
	}
}

// The transcript is an authorization input, so it stays protected with an active intent,
// with the fast path disabled, and through spellings the first path argument hides.
func TestTranscriptProtectedThroughGate(t *testing.T) {
	transcript := "/home/u/.gemini/antigravity/brain/c1/.system_generated/logs/transcript.jsonl"
	calls := map[string]*harness.NormalizedToolCall{
		"write":        {ToolName: "write_to_file", TargetPath: transcript, RawArgs: map[string]any{"TargetFile": transcript}},
		"dot segments": {ToolName: "write_to_file", TargetPath: "/home/u/.gemini/x/../antigravity/brain/c1/.system_generated/logs/transcript.jsonl"},
		"second arg":   {ToolName: "write_to_file", TargetPath: "ok.txt", RawArgs: map[string]any{"TargetFile": "ok.txt", "file_path": transcript}},
		"relative":     {ToolName: "write_to_file", TargetPath: "logs/transcript.jsonl", Cwd: "/home/u/.gemini/antigravity/brain/c1/.system_generated"},
		"cwd":          {ToolName: "run_command", Command: "cat logs/t*", Cwd: "/home/u/.gemini/antigravity/brain/c1/.system_generated"},
		"command":      {ToolName: "run_command", Command: "echo x >> " + transcript},
	}
	off := false
	for name, base := range calls {
		for mode, fastpathOff := range map[string]bool{"fastpath on": false, "fastpath off": true} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				call := *base
				call.Harness = harness.HarnessAntigravity
				call.UserIntent = "edit the transcript"
				cfg := config.DefaultConfig()
				if fastpathOff {
					cfg.FastpathEnabled = &off
				}
				final := traceGateEvaluation(&call, cfg, true).Final
				if final == nil || final.Decision != harness.DecisionDeny || final.Source != "fastpath_tampering" {
					t.Fatalf("expected DENY, got %+v", final)
				}
			})
		}
	}
}

// eval never reads live state: like the session cache, the transcript cannot change its answer.
func TestEvalIgnoresTranscript(t *testing.T) {
	e := newEvalEnv(t, "")
	for _, prompt := range []string{"show me the .env file", "stop"} {
		dir := filepath.Join(e.root, ".gemini", "antigravity", "brain", "c1", ".system_generated", "logs")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "transcript.jsonl")
		if err := os.WriteFile(path, []byte(userRecord(prompt)), 0o600); err != nil {
			t.Fatal(err)
		}
		ws := e.workspace()
		payload := filepath.Join(t.TempDir(), "payload.json")
		body := `{"toolCall":{"name":"view_file","args":{"AbsolutePath":` + jsonString(filepath.Join(ws, ".env")) + `}},"conversationId":"c1","transcriptPath":` + jsonString(path) + `,"workspacePaths":[` + jsonString(ws) + `]}`
		if err := os.WriteFile(payload, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		rep := e.report("--payload="+payload, "--offline")
		requireVerdict(t, rep, harness.DecisionAsk, "fastpath_sensitive")
		if rep.IntentApplied || rep.Harness != string(harness.HarnessAntigravity) {
			t.Errorf("%q: %+v", prompt, rep)
		}
		// An explicit --intent still simulates the hook for an Antigravity payload.
		if with := e.report("--payload="+payload, "--offline", "--intent", "show me the .env file"); !with.IntentApplied || !with.WouldSendToJudge {
			t.Errorf("--intent not applied: %+v", with)
		}
	}
}

func TestEvalReportsCodexHarnessFromStringTurnID(t *testing.T) {
	e := newEvalEnv(t, "")
	ws := e.workspace()
	payload := filepath.Join(t.TempDir(), "payload.json")
	body := `{"session_id":"cx","turn_id":"turn-A","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"cat .env"},"cwd":` + jsonString(ws) + `}`
	if err := os.WriteFile(payload, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rep := e.report("--payload="+payload, "--offline")
	requireVerdict(t, rep, harness.DecisionAsk, "fastpath_sensitive")
	if rep.Harness != string(harness.HarnessCodex) || rep.HookExitCode == nil || *rep.HookExitCode != 2 {
		t.Errorf("%+v", rep)
	}
}

func TestEvalDeniesTranscriptAccessWithFastpathDisabled(t *testing.T) {
	e := newEvalEnv(t, `{"fastpath_enabled":false}`)
	target := filepath.Join(e.root, ".gemini", "antigravity", "brain", "c1", ".system_generated", "logs", "transcript.jsonl")
	rep := e.report("--tool", "view_file", "--target", target, "--offline", "--cwd", e.workspace())
	requireVerdict(t, rep, harness.DecisionDeny, "fastpath_tampering")
}
