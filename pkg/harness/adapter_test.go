package harness

import (
	"encoding/json"
	"testing"
)

func TestParsePayload_Antigravity(t *testing.T) {
	raw := []byte(`{
		"toolCall": {
			"name": "run_command",
			"args": {
				"CommandLine": "git status",
				"Cwd": "C:\\project"
			}
		},
		"workspacePaths": ["C:\\project"],
		"conversationId": "conv-123"
	}`)

	normalized, err := ParsePayload(raw)
	if err != nil {
		t.Fatalf("unexpected error parsing antigravity payload: %v", err)
	}

	if normalized.Harness != HarnessAntigravity {
		t.Errorf("expected harness %s, got %s", HarnessAntigravity, normalized.Harness)
	}
	if normalized.ToolName != "run_command" {
		t.Errorf("expected toolName run_command, got %s", normalized.ToolName)
	}
	if normalized.Command != "git status" {
		t.Errorf("expected command 'git status', got '%s'", normalized.Command)
	}
	if len(normalized.WorkspaceRoots) != 1 || normalized.WorkspaceRoots[0] != "C:\\project" {
		t.Errorf("expected workspace root C:\\project, got %v", normalized.WorkspaceRoots)
	}
}

func TestParsePayload_Claude(t *testing.T) {
	raw := []byte(`{
		"tool_name": "Bash",
		"tool_input": {
			"command": "npm test"
		},
		"cwd": "/home/user/app"
	}`)

	normalized, err := ParsePayload(raw)
	if err != nil {
		t.Fatalf("unexpected error parsing claude payload: %v", err)
	}

	if normalized.Harness != HarnessClaudeCode {
		t.Errorf("expected harness %s, got %s", HarnessClaudeCode, normalized.Harness)
	}
	if normalized.ToolName != "Bash" {
		t.Errorf("expected toolName Bash, got %s", normalized.ToolName)
	}
	if normalized.Command != "npm test" {
		t.Errorf("expected command 'npm test', got '%s'", normalized.Command)
	}
}

func TestParsePayload_EmptyAndInvalid(t *testing.T) {
	if _, err := ParsePayload([]byte("")); err != ErrEmptyPayload {
		t.Errorf("expected ErrEmptyPayload, got %v", err)
	}
	if _, err := ParsePayload([]byte(`{"unknown_field": 123}`)); err != ErrUnknownPayload {
		t.Errorf("expected ErrUnknownPayload, got %v", err)
	}
}

func TestFormatResponse_Antigravity(t *testing.T) {
	res := EvaluationResult{
		Decision: DecisionAllow,
		Reason:   "Benign inspection",
	}

	exitCode, out, err := FormatResponse(HarnessAntigravity, res)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	var parsed AntigravityDecisionOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("failed to unmarshal output: %v", err)
	}
	if parsed.Decision != "allow" || parsed.Reason != "Benign inspection" {
		t.Errorf("unexpected output structure: %+v", parsed)
	}
}

func TestFormatResponse_Claude(t *testing.T) {
	resAsk := EvaluationResult{
		Decision: DecisionAsk,
		Reason:   "Sensitive file access",
	}
	exitCode, out, err := FormatResponse(HarnessClaudeCode, resAsk)
	if err != nil || exitCode != 0 {
		t.Fatalf("unexpected ask formatting result: code=%d err=%v", exitCode, err)
	}

	var parsed ClaudeHookOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("failed to parse claude hook output: %v", err)
	}
	if parsed.HookSpecificOutput.Action != "ask" || parsed.HookSpecificOutput.Message != "Sensitive file access" {
		t.Errorf("unexpected claude output: %+v", parsed)
	}

	resDeny := EvaluationResult{
		Decision: DecisionDeny,
		Reason:   "Destructive command blocked",
	}
	exitCode, out, err = FormatResponse(HarnessClaudeCode, resDeny)
	if err != nil {
		t.Fatalf("unexpected error on deny: %v", err)
	}
	if exitCode != 2 {
		t.Errorf("expected exit code 2 for deny, got %d", exitCode)
	}
	if string(out) != "Destructive command blocked" {
		t.Errorf("expected error message in out, got %s", string(out))
	}
}
