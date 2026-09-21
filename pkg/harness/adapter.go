package harness

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"jev-guard/pkg/session"
)

var (
	ErrEmptyPayload   = errors.New("empty tool call payload received")
	ErrUnknownPayload = errors.New("unable to determine harness type from payload")
)

// ParsePayload inspects raw JSON and normalizes it into a unified tool call representation.
func ParsePayload(raw []byte) (*NormalizedToolCall, error) {
	clean := bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))
	if len(strings.TrimSpace(string(clean))) == 0 {
		return nil, ErrEmptyPayload
	}

	var root map[string]interface{}
	if err := json.Unmarshal(clean, &root); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON payload: %w", err)
	}

	if _, ok := root["toolCall"]; ok {
		return parseAntigravityPayload(clean)
	}

	if _, ok := root["tool_name"]; ok {
		return parseClaudePayload(clean)
	}

	return nil, ErrUnknownPayload
}

func parseAntigravityPayload(raw []byte) (*NormalizedToolCall, error) {
	var payload AntigravityPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("invalid antigravity payload structure: %w", err)
	}

	cmd, target := extractCommandAndTarget(payload.ToolCall.Args)
	cwd := resolveAntigravityCwd(&payload)

	return &NormalizedToolCall{
		Harness:        HarnessAntigravity,
		ToolName:       payload.ToolCall.Name,
		Command:        cmd,
		TargetPath:     target,
		Cwd:            cwd,
		WorkspaceRoots: payload.WorkspacePaths,
		RawArgs:        payload.ToolCall.Args,
		SessionID:      payload.ConversationID,
		TurnID:         payload.InvocationNum,
	}, nil
}

func resolveAntigravityCwd(payload *AntigravityPayload) string {
	if cwd := extractCwd(payload.ToolCall.Args); cwd != "" {
		return cwd
	}
	if payload.Cwd != "" {
		return payload.Cwd
	}
	if len(payload.WorkspacePaths) > 0 && payload.WorkspacePaths[0] != "" {
		return payload.WorkspacePaths[0]
	}
	return ""
}

func parseClaudePayload(raw []byte) (*NormalizedToolCall, error) {
	var payload ClaudePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("invalid claude/codex payload structure: %w", err)
	}

	cmd, target := extractCommandAndTarget(payload.ToolInput)
	cwd := resolveClaudeCwd(&payload)

	sid := payload.SessionID
	if sid == "" && payload.ToolInput != nil {
		if val, exists := payload.ToolInput["session_id"]; exists {
			if strVal, ok := val.(string); ok {
				sid = strVal
			}
		}
	}

	return &NormalizedToolCall{
		Harness:        HarnessClaudeCode,
		ToolName:       payload.ToolName,
		Command:        cmd,
		TargetPath:     target,
		Cwd:            cwd,
		WorkspaceRoots: nil,
		RawArgs:        payload.ToolInput,
		SessionID:      sid,
	}, nil
}

// ParseIngestPayload parses a JSON payload from UserPromptSubmit (Claude) or PreInvocation (Antigravity).
func ParseIngestPayload(raw []byte) (*session.SessionState, error) {
	clean := bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))
	if len(strings.TrimSpace(string(clean))) == 0 {
		return nil, ErrEmptyPayload
	}

	var payload IngestPayload
	if err := json.Unmarshal(clean, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ingest payload: %w", err)
	}

	sid := payload.SessionID
	if sid == "" {
		sid = payload.ConversationID
	}
	if sid == "" {
		sid = "default"
	}

	turn := payload.TurnID
	if turn == 0 {
		turn = payload.InvocationNum
	}
	if turn == 0 {
		turn = payload.StepIdx
	}

	prompt := payload.Prompt
	if prompt == "" {
		prompt = payload.UserPrompt
	}
	if prompt == "" {
		prompt = payload.UserMessage
	}

	return &session.SessionState{
		SessionID: sid,
		TurnID:    turn,
		Prompt:    prompt,
	}, nil
}

func resolveClaudeCwd(payload *ClaudePayload) string {
	if payload.Cwd != "" {
		return payload.Cwd
	}
	return extractCwd(payload.ToolInput)
}

func extractCwd(args map[string]interface{}) string {
	if args == nil {
		return ""
	}

	cwdKeys := []string{"Cwd", "cwd", "working_dir", "workingDir", "workdir", "directory"}
	for _, key := range cwdKeys {
		if val, exists := args[key]; exists {
			if strVal, ok := val.(string); ok && strings.TrimSpace(strVal) != "" {
				return strings.TrimSpace(strVal)
			}
		}
	}
	return ""
}

func extractCommandAndTarget(args map[string]interface{}) (string, string) {
	if args == nil {
		return "", ""
	}

	var cmd string
	cmdKeys := []string{"CommandLine", "command", "cmd", "script"}
	for _, key := range cmdKeys {
		if val, exists := args[key]; exists {
			if strVal, ok := val.(string); ok {
				cmd = strVal
				break
			}
		}
	}

	var target string
	pathKeys := []string{
		"TargetFile", "AbsolutePath", "file_path", "filePath",
		"SearchPath", "search_path", "SearchDirectory",
		"DirectoryPath", "dir_path", "directory",
		"path", "target_path", "targetPath", "target",
		"file", "filename", "Uri", "uri", "Url", "url",
		"dest", "destination", "source", "src",
	}
	for _, key := range pathKeys {
		if val, exists := args[key]; exists {
			if strVal, ok := val.(string); ok && strings.TrimSpace(strVal) != "" {
				target = strings.TrimSpace(strVal)
				break
			}
		}
	}

	return cmd, target
}

// FormatResponse serializes the verdict into the schema expected by the calling harness.
func FormatResponse(harness HarnessType, result EvaluationResult) (int, []byte, error) {
	return FormatResponseForCall(&NormalizedToolCall{Harness: harness}, result)
}

// FormatResponseForCall serializes the verdict taking full normalized tool call context into account.
func FormatResponseForCall(call *NormalizedToolCall, result EvaluationResult) (int, []byte, error) {
	harnessType := HarnessUnknown
	if call != nil {
		harnessType = call.Harness
	}

	switch harnessType {
	case HarnessAntigravity:
		return formatAntigravityResponse(call, result)
	case HarnessClaudeCode, HarnessCodex:
		return formatClaudeResponse(result)
	default:
		return formatDefaultResponse(result)
	}
}

func formatAntigravityResponse(call *NormalizedToolCall, result EvaluationResult) (int, []byte, error) {
	out := AntigravityDecisionOutput{
		Decision: resolveAntigravityDecision(result.Decision),
		Reason:   result.Reason,
	}

	if shouldApplyCommandOverride(call, result.Decision) {
		out.PermissionOverrides = []string{fmt.Sprintf("command(%s)", call.Command)}
	}

	bytes, err := json.Marshal(out)
	if err != nil {
		return 1, nil, fmt.Errorf("failed to marshal antigravity response: %w", err)
	}
	return 0, bytes, nil
}

// resolveAntigravityDecision maps decisions to Antigravity's expected protocol enum.
// In Antigravity, "ask" respects auto-execution/turbo cache, so human escalation requires "force_ask".
func resolveAntigravityDecision(decision Decision) string {
	if decision == DecisionAsk || decision == DecisionForceAsk {
		return "force_ask"
	}
	return string(decision)
}

func shouldApplyCommandOverride(call *NormalizedToolCall, decision Decision) bool {
	if call == nil || strings.TrimSpace(call.Command) == "" {
		return false
	}
	return decision == DecisionAllow || decision == DecisionAsk || decision == DecisionForceAsk
}

func formatClaudeResponse(result EvaluationResult) (int, []byte, error) {
	if isBlockedDecision(result.Decision) {
		// Claude Code and Codex reject tools when hook exits with non-zero (code 2) and prints message to stderr.
		// Since Claude Code and Codex bypass interactive prompts in autonomous/headless modes (--dangerously-skip-permissions, --yolo, -p),
		// any escalation (Ask / ForceAsk) defaults to a fail-safe block (exit code 2).
		return 2, []byte(result.Reason), nil
	}

	out := ClaudeHookOutput{
		HookSpecificOutput: ClaudeHookAction{
			Action:  "allow",
			Message: result.Reason,
		},
	}
	bytes, err := json.Marshal(out)
	if err != nil {
		return 1, nil, fmt.Errorf("failed to marshal claude hook response: %w", err)
	}
	return 0, bytes, nil
}

func isBlockedDecision(decision Decision) bool {
	return decision == DecisionDeny || decision == DecisionAsk || decision == DecisionForceAsk
}

func formatDefaultResponse(result EvaluationResult) (int, []byte, error) {
	exitCode := 0
	if isBlockedDecision(result.Decision) {
		exitCode = 2
	}
	out := map[string]interface{}{
		"decision": string(result.Decision),
		"reason":   result.Reason,
		"source":   result.Source,
	}
	bytes, err := json.Marshal(out)
	if err != nil {
		return 1, nil, fmt.Errorf("failed to marshal default response: %w", err)
	}
	return exitCode, bytes, nil
}
