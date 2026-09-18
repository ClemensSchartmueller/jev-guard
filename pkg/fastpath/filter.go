package fastpath

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/typesafe-ai/jev-guard/pkg/harness"
)

// Filter provides sub-millisecond static gating before external AI evaluation.
type Filter struct {
	catastrophicRegexes []*regexp.Regexp
	sensitiveSubstrings []string
	safeTools           map[string]bool
	safeCommands        []string
}

// NewDefaultFilter constructs a fast-path filter preloaded with standard safety rules.
func NewDefaultFilter() *Filter {
	return &Filter{
		catastrophicRegexes: compileCatastrophicPatterns(),
		sensitiveSubstrings: defaultSensitiveSubstrings(),
		safeTools:           defaultSafeTools(),
		safeCommands:        defaultSafeCommands(),
	}
}

// Evaluate checks the tool call against static rules. Returns nil if semantic analysis is needed.
func (f *Filter) Evaluate(call *harness.NormalizedToolCall) *harness.EvaluationResult {
	combined := strings.ToLower(call.Command + " " + call.TargetPath)

	if reason := f.checkCatastrophic(combined); reason != "" {
		return &harness.EvaluationResult{
			Decision:   harness.DecisionDeny,
			Reason:     reason,
			Source:     "fastpath_catastrophic",
			Confidence: 1.0,
		}
	}

	if reason := f.checkSensitive(combined, call.TargetPath); reason != "" {
		return &harness.EvaluationResult{
			Decision:   harness.DecisionAsk,
			Reason:     reason,
			Source:     "fastpath_sensitive",
			Confidence: 1.0,
		}
	}

	if f.isSafeRead(call) {
		return &harness.EvaluationResult{
			Decision:   harness.DecisionAllow,
			Reason:     "Safe read-only operation verified by fast-path",
			Source:     "fastpath_whitelist",
			Confidence: 1.0,
		}
	}

	return nil
}

func (f *Filter) checkCatastrophic(text string) string {
	for _, re := range f.catastrophicRegexes {
		if re.MatchString(text) {
			return "Catastrophic command pattern detected: " + re.String()
		}
	}
	return ""
}

func (f *Filter) checkSensitive(text, targetPath string) string {
	baseName := strings.ToLower(filepath.Base(targetPath))
	for _, s := range f.sensitiveSubstrings {
		if strings.Contains(text, s) || strings.Contains(baseName, s) {
			return "Access to sensitive file or credential pattern: " + s
		}
	}
	return ""
}

func (f *Filter) isSafeRead(call *harness.NormalizedToolCall) bool {
	if f.safeTools[call.ToolName] {
		return true
	}

	trimmedCmd := strings.TrimSpace(strings.ToLower(call.Command))
	if trimmedCmd == "" {
		return false
	}

	for _, safeCmd := range f.safeCommands {
		if trimmedCmd == safeCmd || strings.HasPrefix(trimmedCmd, safeCmd+" ") {
			// Avoid allowing if piped or chained into mutators
			if !containsChainingOperators(trimmedCmd) {
				return true
			}
		}
	}
	return false
}

func containsChainingOperators(cmd string) bool {
	operators := []string{";", "&&", "||", "|", ">", ">>"}
	for _, op := range operators {
		if strings.Contains(cmd, op) {
			return true
		}
	}
	return false
}

func compileCatastrophicPatterns() []*regexp.Regexp {
	patterns := []string{
		`rm\s+(-[a-zA-Z0-9]*r[a-zA-Z0-9]*f[a-zA-Z0-9]*|-rf|-fr)\s+(/|/\*|~|~\*)(\s|$|;)`,
		`rm\s+(-[a-zA-Z0-9]*r[a-zA-Z0-9]*f[a-zA-Z0-9]*|-rf|-fr)\s+--no-preserve-root`,
		`:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:`,
		`format\s+[a-zA-Z]:`,
		`mkfs\.[a-zA-Z0-9]+`,
		`dd\s+if=/dev/zero\s+of=/dev/[a-zA-Z0-9]+`,
		`rd\s+/s\s+/q\s+[c-zC-Z]:\\`,
	}
	var res []*regexp.Regexp
	for _, p := range patterns {
		if re, err := regexp.Compile(p); err == nil {
			res = append(res, re)
		}
	}
	return res
}

func defaultSensitiveSubstrings() []string {
	return []string{
		".env",
		"id_rsa",
		"id_ed25519",
		".ssh/",
		".aws/",
		"credentials.json",
		".pem",
		".key",
		"serviceaccount.json",
	}
}

func defaultSafeTools() map[string]bool {
	return map[string]bool{
		"view_file":        true,
		"list_dir":         true,
		"grep_search":      true,
		"find_by_name":     true,
		"read_url_content": true,
	}
}

func defaultSafeCommands() []string {
	return []string{
		"git status",
		"git diff",
		"git log",
		"git branch",
		"git show",
		"ls",
		"dir",
		"pwd",
		"echo",
		"whoami",
		"which",
		"where.exe",
		"node -v",
		"go version",
		"python --version",
	}
}
