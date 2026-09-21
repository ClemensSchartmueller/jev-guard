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
		if strings.TrimSpace(call.UserIntent) != "" {
			// Defer to TypeSafe AI for semantic intent verification.
			// Never fall through to trusted read operations for sensitive files.
			return nil
		}
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
		return "Direct access to jev-guard security directory or configuration file is prohibited"
	}

	lowerCmd := strings.ToLower(call.Command)
	if strings.Contains(lowerCmd, ".jevguard") || strings.Contains(lowerCmd, "jevguard.json") {
		return "Access to jev-guard configuration or session state via command is prohibited"
	}

	return ""
}

func (f *Filter) checkSensitive(call *harness.NormalizedToolCall) string {
	targetRaw := call.TargetPath
	if isFileURI(targetRaw) {
		targetRaw = extractFilePathFromURI(targetRaw)
	}
	target := filepath.ToSlash(strings.ToLower(targetRaw))
	cmd := filepath.ToSlash(strings.ToLower(call.Command))
	baseName := strings.ToLower(filepath.Base(targetRaw))
	cmdTokens := strings.Fields(cmd)

	for _, s := range f.sensitiveFiles {
		lowerPattern := filepath.ToSlash(strings.ToLower(s))

		// 1. Glob matching on target path / basename
		if baseName != "" && baseName != "." {
			if matched, _ := filepath.Match(lowerPattern, baseName); matched {
				return "Access to sensitive file or credential pattern: " + s
			}
		}
		if target != "" {
			if matched, _ := filepath.Match(lowerPattern, target); matched {
				return "Access to sensitive file or credential pattern: " + s
			}
		}

		// 2. Glob matching on command arguments
		if strings.Contains(lowerPattern, "*") || strings.Contains(lowerPattern, "?") {
			for _, token := range cmdTokens {
				cleanToken := strings.Trim(token, `"'`)
				tokenBase := strings.ToLower(filepath.Base(cleanToken))
				if matched, _ := filepath.Match(lowerPattern, tokenBase); matched {
					return "Access to sensitive file or credential pattern: " + s
				}
			}
		}

		// 3. Substring matching
		cleanPattern := strings.TrimPrefix(lowerPattern, "*")
		if cleanPattern != "" {
			if strings.Contains(target, cleanPattern) || strings.Contains(baseName, cleanPattern) || strings.Contains(cmd, cleanPattern) {
				return "Access to sensitive file or credential pattern: " + s
			}
			if strings.HasSuffix(cleanPattern, "/") {
				cleanPatternTrimmed := strings.TrimSuffix(cleanPattern, "/")
				if strings.HasSuffix(target, "/"+cleanPatternTrimmed) || target == cleanPatternTrimmed || strings.Contains(target, "/"+cleanPatternTrimmed+"/") {
					return "Access to sensitive file or credential pattern: " + s
				}
				if strings.Contains(cmd, "/"+cleanPatternTrimmed+"/") || strings.Contains(cmd, " "+cleanPatternTrimmed) {
					return "Access to sensitive file or credential pattern: " + s
				}
			}
		}
	}
	return ""
}

func (f *Filter) checkBoundaryEscape(call *harness.NormalizedToolCall) string {
	target := strings.TrimSpace(call.TargetPath)
	if target == "" || isURL(target) {
		return ""
	}

	if isFileURI(target) {
		target = extractFilePathFromURI(target)
	}

	checker := f.resolveBoundaryChecker(call)
	if checker == nil {
		return fmt.Sprintf("Workspace boundaries cannot be resolved for target: %s", target)
	}

	contained, err := checker.IsPathContained(target, call.Cwd)
	if err != nil {
		return fmt.Sprintf("Target path cannot be verified within workspace: %s (%v)", target, err)
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
	if isSafeReadTool(call) {
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

	matched := false
	var matchedPrefix string
	for _, trusted := range f.trustedCommands {
		trustedLower := strings.ToLower(trusted)
		if trimmedCmd == trustedLower || strings.HasPrefix(trimmedCmd, trustedLower+" ") {
			matched = true
			matchedPrefix = trustedLower
			break
		}
	}

	if !matched {
		return false
	}

	return f.areCommandArgsContained(trimmedCmd, matchedPrefix, call)
}

func (f *Filter) areCommandArgsContained(cmd, trustedPrefix string, call *harness.NormalizedToolCall) bool {
	argsStr := strings.TrimSpace(strings.TrimPrefix(cmd, trustedPrefix))
	if argsStr == "" {
		return true
	}

	checker := f.resolveBoundaryChecker(call)
	if checker == nil {
		return false
	}

	tokens := strings.Fields(argsStr)
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		cleanArg := strings.Trim(token, `"'`)

		// Disallow file output/writing flags in trusted read commands - defer to semantic evaluation
		lowerArg := strings.ToLower(cleanArg)
		if lowerArg == "-o" || strings.HasPrefix(lowerArg, "-o=") || strings.HasPrefix(lowerArg, "--output") || strings.HasPrefix(lowerArg, "--output-directory") {
			return false
		}

		// Inspect --flag=path syntax
		if strings.HasPrefix(cleanArg, "-") {
			if strings.Contains(cleanArg, "=") {
				parts := strings.SplitN(cleanArg, "=", 2)
				val := strings.Trim(parts[1], `"'`)
				if isPotentialPath(val) {
					contained, err := checker.IsPathContained(val, call.Cwd)
					if err != nil || !contained {
						return false
					}
				}
			}
			continue
		}

		if isPotentialPath(cleanArg) {
			contained, err := checker.IsPathContained(cleanArg, call.Cwd)
			if err != nil || !contained {
				return false
			}
		}
	}

	return true
}

func isPotentialPath(arg string) bool {
	if strings.HasPrefix(arg, "/") || strings.HasPrefix(arg, "\\") {
		return true
	}
	if strings.Contains(arg, "..") || strings.Contains(arg, "/") || strings.Contains(arg, "\\") {
		return true
	}
	if len(arg) >= 2 && arg[1] == ':' {
		return true
	}
	return false
}

func isSafeReadTool(call *harness.NormalizedToolCall) bool {
	if call == nil {
		return false
	}
	toolName := strings.ToLower(strings.TrimSpace(call.ToolName))
	switch toolName {
	case "view_file", "view", "read_file", "readlocalfile",
		"list_dir", "ls", "grep_search", "grep", "find_by_name", "glob":
		return true
	case "read_resource":
		target := strings.TrimSpace(call.TargetPath)
		if isURL(target) || (isCustomURI(target) && !isFileURI(target)) {
			return false
		}
		return true
	default:
		return false
	}
}

func containsChainingOperators(cmd string) bool {
	operators := []string{";", "&", "|", ">", "<", "`", "$", "(", ")", "{", "}", "\n", "\r"}
	for _, op := range operators {
		if strings.Contains(cmd, op) {
			return true
		}
	}
	return false
}

func isURL(p string) bool {
	lower := strings.ToLower(p)
	if strings.HasPrefix(lower, "file://") {
		return false
	}
	return strings.Contains(lower, "://")
}

func isFileURI(p string) bool {
	return strings.HasPrefix(strings.ToLower(p), "file://")
}

func isCustomURI(p string) bool {
	lower := strings.ToLower(p)
	return strings.Contains(lower, "://")
}

func extractFilePathFromURI(uriStr string) string {
	lower := strings.ToLower(uriStr)
	if strings.HasPrefix(lower, "file:///") {
		trimmed := uriStr[len("file:///"):]
		// On Windows: file:///C:/path -> C:/path
		if len(trimmed) >= 2 && isDriveLetter(trimmed[0]) && trimmed[1] == ':' {
			return trimmed
		}
		// On POSIX: file:///etc/passwd -> /etc/passwd
		return "/" + trimmed
	}
	if strings.HasPrefix(lower, "file://") {
		return uriStr[len("file://"):]
	}
	return uriStr
}

func isDriveLetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}
