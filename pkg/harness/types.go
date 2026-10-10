package harness

import "encoding/json"

// HarnessType represents the calling agent platform.
type HarnessType string

const (
	HarnessClaudeCode  HarnessType = "claude-code"
	HarnessCodex       HarnessType = "codex"
	HarnessAntigravity HarnessType = "antigravity"
	HarnessUnknown     HarnessType = "unknown"
)

// Decision represents the final tool gating policy verdict.
type Decision string

const (
	DecisionAllow    Decision = "allow"
	DecisionAsk      Decision = "ask"
	DecisionForceAsk Decision = "force_ask"
	DecisionDeny     Decision = "deny"
)

// NormalizedToolCall provides a unified abstraction over varying agent input shapes.
type NormalizedToolCall struct {
	Harness        HarnessType
	ToolName       string
	Command        string
	TargetPath     string
	Cwd            string
	WorkspaceRoots []string
	RawArgs        map[string]interface{}
	SessionID      string
	TurnID         int
	// TurnKey is an opaque string turn identifier (Codex turn_id). Empty for Claude/Antigravity.
	TurnKey    string
	UserIntent string
}

// ClaudePayload represents the payload sent by Claude Code and Codex hooks.
type ClaudePayload struct {
	ToolName  string                 `json:"tool_name"`
	ToolInput map[string]interface{} `json:"tool_input"`
	Cwd       string                 `json:"cwd"`
	SessionID string                 `json:"session_id,omitempty"`
	TurnID    TurnValue              `json:"turn_id,omitempty"`
}

// AntigravityPayload represents the payload sent by Antigravity pre-tool hooks.
type AntigravityPayload struct {
	ToolCall       AntigravityToolCall `json:"toolCall"`
	WorkspacePaths []string            `json:"workspacePaths"`
	ConversationID string              `json:"conversationId"`
	StepIdx        int                 `json:"stepIdx,omitempty"`
	InvocationNum  int                 `json:"invocationNum,omitempty"`
	Cwd            string              `json:"cwd"`
}

// IngestPayload represents prompt-bearing hook payloads or explicit ingest JSON.
type IngestPayload struct {
	SessionID      string    `json:"session_id,omitempty"`
	ConversationID string    `json:"conversationId,omitempty"`
	TurnID         TurnValue `json:"turn_id,omitempty"`
	InvocationNum  int       `json:"invocationNum,omitempty"`
	StepIdx        int       `json:"stepIdx,omitempty"`
	Prompt         string    `json:"prompt,omitempty"`
	UserPrompt     string    `json:"user_prompt,omitempty"`
	UserMessage    string    `json:"userMessage,omitempty"`
}

// TurnValue accepts a JSON turn_id that is either a number (integer turn) or a
// string (opaque Codex turn key) without failing to unmarshal.
type TurnValue struct {
	Num int
	Key string
}

// UnmarshalJSON implements json.Unmarshaler. Unsupported shapes are ignored.
func (t *TurnValue) UnmarshalJSON(data []byte) error {
	*t = TurnValue{}
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		t.Key = s
		return nil
	}
	var n float64
	if err := json.Unmarshal(data, &n); err == nil {
		t.Num = int(n)
	}
	return nil
}

// AntigravityToolCall holds the tool call name and arguments from Antigravity.
type AntigravityToolCall struct {
	Name string                 `json:"name"`
	Args map[string]interface{} `json:"args"`
}

// ClaudeHookOutput shapes the stdout for Claude Code hook responses.
type ClaudeHookOutput struct {
	HookSpecificOutput ClaudeHookAction `json:"hookSpecificOutput"`
}

// ClaudeHookAction defines the PreToolUse decision schema for Claude Code.
type ClaudeHookAction struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"` // "allow", "deny", or "ask"
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
}

// AntigravityDecisionOutput shapes the stdout for Antigravity pre-tool responses.
type AntigravityDecisionOutput struct {
	Decision            string   `json:"decision"` // "allow", "ask", or "deny"
	Reason              string   `json:"reason,omitempty"`
	PermissionOverrides []string `json:"permissionOverrides,omitempty"`
}

// EvaluationResult contains the decision, reason, and telemetry for the invocation.
type EvaluationResult struct {
	Decision   Decision
	Reason     string
	Source     string // "fastpath", "typesafe", or "policy_fallback"
	Confidence float64
}
