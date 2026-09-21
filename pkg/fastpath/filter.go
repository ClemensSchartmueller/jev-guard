package fastpath

import (
	"fmt"
	"path/filepath"
	"strings"

	"jev-guard/pkg/boundary"
	"jev-guard/pkg/config"
	"jev-guard/pkg/harness"
	"jev-guard/pkg/session"
)

// BoundaryChecker verifies whether a target path is contained within workspace boundaries.
type BoundaryChecker interface {
	IsPathContained(targetPath string, cwd string) (bool, error)
}

// Filter provides sub-millisecond local invariant enforcement (sensitive credentials, workspace boundaries)
// and latency caching for trusted read-only inspection commands before external AI evaluation.
type Filter struct {
	boundaryChecker BoundaryChecker
	sensitiveFiles  []string
	trustedCommands []string
}

// NewFilter constructs a fast-path filter with injected boundary checker and configuration.
func NewFilter(checker BoundaryChecker, cfg *config.Config) *Filter {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	return &Filter{
		boundaryChecker: checker,
		sensitiveFiles:  cfg.SensitiveFiles,
		trustedCommands: cfg.TrustedCommands,
	}
}

// NewDefaultFilter constructs a fast-path filter preloaded with default configuration.
func NewDefaultFilter() *Filter {
	return NewFilter(nil, config.DefaultConfig())
}

// Evaluate checks the tool call against local invariants and latency cache.
// Returns nil if semantic analysis by TypeSafe AI (Jev) is needed.
func (f *Filter) Evaluate(call *harness.NormalizedToolCall) *harness.EvaluationResult {
	if reason := f.checkAntiTampering(call); reason != "" {
		return &harness.EvaluationResult{
			Decision:   harness.DecisionDeny,
			Reason:     reason,
			Source:     "fastpath_tampering",
			Confidence: 1.0,
		}
	}

	if reason := f.checkSensitive(call); reason != "" {
		return &harness.EvaluationResult{
			Decision:   harness.DecisionAsk,
			Reason:     reason,
			Source:     "fastpath_sensitive",
			Confidence: 1.0,
		}
	}

	if reason := f.checkBoundaryEscape(call); reason != "" {
		return &harness.EvaluationResult{
			Decision:   harness.DecisionAsk,
			Reason:     reason,
			Source:     "fastpath_boundary",
			Confidence: 1.0,
		}
	}

	if f.isTrustedOperation(call) {
		return &harness.EvaluationResult{
			Decision:   harness.DecisionAllow,
			Reason:     "Trusted read-only operation verified by fast-path",
			Source:     "fastpath_trusted",
			Confidence: 1.0,
		}
	}

	return nil
}

func (f *Filter) checkAntiTampering(call *harness.NormalizedToolCall) string {
	if call == nil {
		return ""
	}

	if session.IsJevguardPath(call.TargetPath) {
		return "Direct access to jev-guard security directory is prohibited"
	}

	lowerCmd := strings.ToLower(call.Command)
	if strings.Contains(lowerCmd, ".jevguard") {
		return "Access to jev-guard configuration or session state via command is prohibited"
	}

	return ""
}

func (f *Filter) checkSensitive(call *harness.NormalizedToolCall) string {
	// If the user has active context intent, defer sensitive evaluation to TypeSafe AI
	if call != nil && strings.TrimSpace(call.UserIntent) != "" {
		return ""
	}

	target := strings.ToLower(call.TargetPath)
	cmd := strings.ToLower(call.Command)
	baseName := strings.ToLower(filepath.Base(call.TargetPath))

	for _, s := range f.sensitiveFiles {
		lowerPattern := strings.ToLower(s)
		if strings.Contains(target, lowerPattern) || strings.Contains(baseName, lowerPattern) || strings.Contains(cmd, lowerPattern) {
			return "Access to sensitive file or credential pattern: " + s
		}
	}
	return ""
}

func (f *Filter) checkBoundaryEscape(call *harness.NormalizedToolCall) string {
	target := strings.TrimSpace(call.TargetPath)
	if target == "" || isURL(target) {
		return ""
	}

	checker := f.resolveBoundaryChecker(call)
	if checker == nil {
		return ""
	}

	contained, err := checker.IsPathContained(target, call.Cwd)
	if err != nil {
		return ""
	}

	if !contained {
		return fmt.Sprintf("Target path escapes workspace boundaries: %s", target)
	}

	return ""
}

func (f *Filter) resolveBoundaryChecker(call *harness.NormalizedToolCall) BoundaryChecker {
	if f.boundaryChecker != nil {
		return f.boundaryChecker
	}

	resolver, err := boundary.NewResolver(call.WorkspaceRoots, call.Cwd)
	if err != nil {
		return nil
	}
	return resolver
}

func (f *Filter) isTrustedOperation(call *harness.NormalizedToolCall) bool {
	if isSafeReadTool(call.ToolName) {
		return true
	}
	return f.isTrustedCommand(call)
}

func (f *Filter) isTrustedCommand(call *harness.NormalizedToolCall) bool {
	trimmedCmd := strings.TrimSpace(strings.ToLower(call.Command))
	if trimmedCmd == "" {
		return false
	}

	if containsChainingOperators(trimmedCmd) {
		return false
	}

	for _, trusted := range f.trustedCommands {
		trustedLower := strings.ToLower(trusted)
		if trimmedCmd == trustedLower || strings.HasPrefix(trimmedCmd, trustedLower+" ") {
			return true
		}
	}
	return false
}

func isSafeReadTool(toolName string) bool {
	switch strings.ToLower(strings.TrimSpace(toolName)) {
	case "view_file", "view", "read_file", "readlocalfile",
		"list_dir", "ls", "grep_search", "grep", "find_by_name", "glob",
		"read_url_content", "read_resource":
		return true
	default:
		return false
	}
}

func containsChainingOperators(cmd string) bool {
	operators := []string{";", "&&", "||", "|", ">", ">>", "`", "$("}
	for _, op := range operators {
		if strings.Contains(cmd, op) {
			return true
		}
	}
	return false
}

func isURL(p string) bool {
	lower := strings.ToLower(p)
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}
