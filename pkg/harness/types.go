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
	UserIntent     string
}

// ClaudePayload represents the payload sent by Claude Code and Codex hooks.
type ClaudePayload struct {
	ToolName  string                 `json:"tool_name"`
	ToolInput map[string]interface{} `json:"tool_input"`
	Cwd       string                 `json:"cwd"`
	SessionID string                 `json:"session_id,omitempty"`
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

// IngestPayload represents lifecycle ingestion inputs (e.g. UserPromptSubmit, PreInvocation).
type IngestPayload struct {
	SessionID      string `json:"session_id,omitempty"`
	ConversationID string `json:"conversationId,omitempty"`
	TurnID         int    `json:"turn_id,omitempty"`
	InvocationNum  int    `json:"invocationNum,omitempty"`
	StepIdx        int    `json:"stepIdx,omitempty"`
	Prompt         string `json:"prompt,omitempty"`
	UserPrompt     string `json:"user_prompt,omitempty"`
	UserMessage    string `json:"userMessage,omitempty"`
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
