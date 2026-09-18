package harness

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
	DecisionAllow Decision = "allow"
	DecisionAsk   Decision = "ask"
	DecisionDeny  Decision = "deny"
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
}

// ClaudePayload represents the payload sent by Claude Code and Codex hooks.
type ClaudePayload struct {
	ToolName  string                 `json:"tool_name"`
	ToolInput map[string]interface{} `json:"tool_input"`
	Cwd       string                 `json:"cwd"`
}

// AntigravityPayload represents the payload sent by Antigravity pre-tool hooks.
type AntigravityPayload struct {
	ToolCall       AntigravityToolCall `json:"toolCall"`
	WorkspacePaths []string            `json:"workspacePaths"`
	ConversationID string              `json:"conversationId"`
	Cwd            string              `json:"cwd"`
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

// ClaudeHookAction defines the action decision and optional message for Claude Code.
type ClaudeHookAction struct {
	Action  string `json:"action"` // "allow" or "ask"
	Message string `json:"message,omitempty"`
}

// AntigravityDecisionOutput shapes the stdout for Antigravity pre-tool responses.
type AntigravityDecisionOutput struct {
	Decision            string   `json:"decision"` // "allow", "ask", or "deny"
	Reason              string   `json:"reason,omitempty"`
	PermissionOverrides []string `json:"permissionOverrides,omitempty"`
}

// EvaluationResult contains the decision, reason, and telemetry for the invocation.
type EvaluationResult struct {
	Decision  Decision
	Reason    string
	Source    string // "fastpath", "typesafe", or "policy_fallback"
	Confidence float64
}
