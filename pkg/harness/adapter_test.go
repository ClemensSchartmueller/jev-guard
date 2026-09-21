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
	if normalized.Cwd != "C:\\project" {
		t.Errorf("expected cwd 'C:\\project', got '%s'", normalized.Cwd)
	}
	if len(normalized.WorkspaceRoots) != 1 || normalized.WorkspaceRoots[0] != "C:\\project" {
		t.Errorf("expected workspace root C:\\project, got %v", normalized.WorkspaceRoots)
	}
}

func TestParsePayload_AntigravityFallback(t *testing.T) {
	raw := []byte(`{
		"toolCall": {
			"name": "write_to_file",
			"args": {
				"TargetFile": "C:\\project\\file.txt",
				"CodeContent": "hello"
			}
		},
		"workspacePaths": ["C:\\project"],
		"conversationId": "conv-456"
	}`)

	normalized, err := ParsePayload(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if normalized.Cwd != "C:\\project" {
		t.Errorf("expected cwd to fallback to workspace path 'C:\\project', got '%s'", normalized.Cwd)
	}
	if normalized.TargetPath != "C:\\project\\file.txt" {
		t.Errorf("expected target path 'C:\\project\\file.txt', got '%s'", normalized.TargetPath)
	}
}

func TestParsePayload_ClaudeInputCwd(t *testing.T) {
	raw := []byte(`{
		"tool_name": "Bash",
		"tool_input": {
			"command": "go test ./...",
			"cwd": "/repo/subfolder"
		}
	}`)

	normalized, err := ParsePayload(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if normalized.Cwd != "/repo/subfolder" {
		t.Errorf("expected cwd from tool_input '/repo/subfolder', got '%s'", normalized.Cwd)
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

func TestParsePayload_ClaudeView(t *testing.T) {
	raw := []byte(`{
		"tool_name": "View",
		"tool_input": {
			"file_path": "/etc/shadow"
		},
		"cwd": "/home/user/app"
	}`)

	normalized, err := ParsePayload(raw)
	if err != nil {
		t.Fatalf("unexpected error parsing claude view payload: %v", err)
	}

	if normalized.Harness != HarnessClaudeCode {
		t.Errorf("expected harness %s, got %s", HarnessClaudeCode, normalized.Harness)
	}
	if normalized.ToolName != "View" {
		t.Errorf("expected toolName View, got %s", normalized.ToolName)
	}
	if normalized.TargetPath != "/etc/shadow" {
		t.Errorf("expected targetPath '/etc/shadow', got '%s'", normalized.TargetPath)
	}
}

func TestParsePayload_CodexReadFile(t *testing.T) {
	raw := []byte(`{
		"tool_name": "read_file",
		"tool_input": {
			"path": "C:\\Windows\\system.ini"
		},
		"cwd": "C:\\myproject"
	}`)

	normalized, err := ParsePayload(raw)
	if err != nil {
		t.Fatalf("unexpected error parsing codex read_file payload: %v", err)
	}

	if normalized.ToolName != "read_file" {
		t.Errorf("expected toolName read_file, got %s", normalized.ToolName)
	}
	if normalized.TargetPath != "C:\\Windows\\system.ini" {
		t.Errorf("expected targetPath 'C:\\Windows\\system.ini', got '%s'", normalized.TargetPath)
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

func TestFormatResponseForCall_AntigravityPermissionOverrides_Allow(t *testing.T) {
	call := &NormalizedToolCall{
		Harness:  HarnessAntigravity,
		ToolName: "run_command",
		Command:  "go test -v ./pkg/fastpath",
	}
	res := EvaluationResult{
		Decision: DecisionAllow,
		Reason:   "Verified safe by TypeSafe AI",
	}

	exitCode, out, err := FormatResponseForCall(call, res)
	if err != nil || exitCode != 0 {
		t.Fatalf("unexpected error or exitCode: err=%v, code=%d", err, exitCode)
	}

	var parsed AntigravityDecisionOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("failed to unmarshal output: %v", err)
	}
	if len(parsed.PermissionOverrides) != 1 || parsed.PermissionOverrides[0] != "command(go test -v ./pkg/fastpath)" {
		t.Errorf("expected permission override 'command(go test -v ./pkg/fastpath)', got %v", parsed.PermissionOverrides)
	}
}

func TestFormatResponseForCall_AntigravityPermissionOverrides_Ask(t *testing.T) {
	call := &NormalizedToolCall{
		Harness:  HarnessAntigravity,
		ToolName: "run_command",
		Command:  "npm test",
	}
	res := EvaluationResult{
		Decision: DecisionAsk,
		Reason:   "Requires user confirmation",
	}

	exitCode, out, err := FormatResponseForCall(call, res)
	if err != nil || exitCode != 0 {
		t.Fatalf("unexpected error or exitCode: err=%v, code=%d", err, exitCode)
	}

	var parsed AntigravityDecisionOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("failed to unmarshal output: %v", err)
	}
	if parsed.Decision != "force_ask" {
		t.Errorf("expected decision 'force_ask' for Antigravity ask escalation, got '%s'", parsed.Decision)
	}
	if len(parsed.PermissionOverrides) != 1 || parsed.PermissionOverrides[0] != "command(npm test)" {
		t.Errorf("expected permission override 'command(npm test)', got %v", parsed.PermissionOverrides)
	}
}

func TestFormatResponseForCall_AntigravityForceAsk(t *testing.T) {
	call := &NormalizedToolCall{
		Harness:  HarnessAntigravity,
		ToolName: "run_command",
		Command:  "git diff .env",
	}
	res := EvaluationResult{
		Decision: DecisionForceAsk,
		Reason:   "Sensitive environment file accessed",
	}

	exitCode, out, err := FormatResponseForCall(call, res)
	if err != nil || exitCode != 0 {
		t.Fatalf("unexpected error or exitCode: err=%v, code=%d", err, exitCode)
	}

	var parsed AntigravityDecisionOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("failed to unmarshal output: %v", err)
	}
	if parsed.Decision != "force_ask" {
		t.Errorf("expected decision 'force_ask', got '%s'", parsed.Decision)
	}
	if len(parsed.PermissionOverrides) != 1 || parsed.PermissionOverrides[0] != "command(git diff .env)" {
		t.Errorf("expected permission override 'command(git diff .env)', got %v", parsed.PermissionOverrides)
	}
}

func TestFormatResponseForCall_AntigravityPermissionOverrides_Deny(t *testing.T) {
	call := &NormalizedToolCall{
		Harness:  HarnessAntigravity,
		ToolName: "run_command",
		Command:  "rm -rf /",
	}
	res := EvaluationResult{
		Decision: DecisionDeny,
		Reason:   "Catastrophic deletion blocked",
	}

	exitCode, out, err := FormatResponseForCall(call, res)
	if err != nil || exitCode != 0 {
		t.Fatalf("unexpected error: err=%v, code=%d", err, exitCode)
	}

	var parsed AntigravityDecisionOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("failed to unmarshal output: %v", err)
	}
	if len(parsed.PermissionOverrides) != 0 {
		t.Errorf("expected no permission overrides on deny, got %v", parsed.PermissionOverrides)
	}
}

func TestFormatResponseForCall_AntigravityPermissionOverrides_NoCommand(t *testing.T) {
	call := &NormalizedToolCall{
		Harness:    HarnessAntigravity,
		ToolName:   "write_to_file",
		TargetPath: "test.go",
	}
	res := EvaluationResult{
		Decision: DecisionAllow,
		Reason:   "File write allowed",
	}

	exitCode, out, err := FormatResponseForCall(call, res)
	if err != nil || exitCode != 0 {
		t.Fatalf("unexpected error: err=%v, code=%d", err, exitCode)
	}

	var parsed AntigravityDecisionOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("failed to unmarshal output: %v", err)
	}
	if len(parsed.PermissionOverrides) != 0 {
		t.Errorf("expected no permission overrides for tool without command, got %v", parsed.PermissionOverrides)
	}
}

func TestFormatResponse_Claude(t *testing.T) {
	resAllow := EvaluationResult{
		Decision: DecisionAllow,
		Reason:   "Safe read command",
	}
	exitCode, out, err := FormatResponse(HarnessClaudeCode, resAllow)
	if err != nil || exitCode != 0 {
		t.Fatalf("unexpected allow formatting result: code=%d err=%v", exitCode, err)
	}

	var parsed ClaudeHookOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("failed to parse claude hook output: %v", err)
	}
	if parsed.HookSpecificOutput.Action != "allow" || parsed.HookSpecificOutput.Message != "Safe read command" {
		t.Errorf("unexpected claude output: %+v", parsed)
	}

	// DecisionAsk must fail-safe to exit code 2 to prevent silent bypass in bypass/autonomous modes
	resAsk := EvaluationResult{
		Decision: DecisionAsk,
		Reason:   "Sensitive file access",
	}
	exitCode, out, err = FormatResponse(HarnessClaudeCode, resAsk)
	if err != nil {
		t.Fatalf("unexpected error on ask: %v", err)
	}
	if exitCode != 2 {
		t.Errorf("expected exit code 2 for ask escalation in Claude Code, got %d", exitCode)
	}
	if string(out) != "Sensitive file access" {
		t.Errorf("expected error message in out, got %s", string(out))
	}

	// DecisionForceAsk must also fail-safe to exit code 2
	resForceAsk := EvaluationResult{
		Decision: DecisionForceAsk,
		Reason:   "Forced prompt escalation",
	}
	exitCode, out, err = FormatResponse(HarnessCodex, resForceAsk)
	if err != nil {
		t.Fatalf("unexpected error on force_ask: %v", err)
	}
	if exitCode != 2 {
		t.Errorf("expected exit code 2 for force_ask in Codex, got %d", exitCode)
	}
	if string(out) != "Forced prompt escalation" {
		t.Errorf("expected error message in out, got %s", string(out))
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

func TestParsePayload_AntigravityGrepSearch(t *testing.T) {
	raw := []byte(`{
		"toolCall": {
			"name": "grep_search",
			"args": {
				"SearchPath": "/outside/workspace",
				"Query": "secret"
			}
		},
		"workspacePaths": ["/inside/workspace"],
		"conversationId": "conv-grep"
	}`)

	call, err := ParsePayload(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if call.TargetPath != "/outside/workspace" {
		t.Errorf("expected target path '/outside/workspace', got '%s'", call.TargetPath)
	}
}

func TestParsePayload_AntigravityReadResource(t *testing.T) {
	raw := []byte(`{
		"toolCall": {
			"name": "read_resource",
			"args": {
				"Uri": "file:///path/to/resource.txt"
			}
		},
		"workspacePaths": ["/workspace"],
		"conversationId": "conv-res"
	}`)

	call, err := ParsePayload(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if call.TargetPath != "file:///path/to/resource.txt" {
		t.Errorf("expected target path 'file:///path/to/resource.txt', got '%s'", call.TargetPath)
	}
}

func TestParsePayload_CodexApplyPatch(t *testing.T) {
	raw := []byte(`{
		"tool_name": "apply_patch",
		"tool_input": {
			"file": "/repo/main.go",
			"patch": "*** main.go\n--- main.go\n"
		},
		"cwd": "/repo"
	}`)

	call, err := ParsePayload(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if call.TargetPath != "/repo/main.go" {
		t.Errorf("expected target path '/repo/main.go', got '%s'", call.TargetPath)
	}
}

