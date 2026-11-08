package fastpath

import (
	"path"
	"strings"

	"jev-guard/pkg/harness"
	"jev-guard/pkg/session"
)

// SourceAntiTamperingLimit is reported when a command is too large for anti-tampering to read
// word by word. The verdict is ASK, as for the transcript guard's limit.
const SourceAntiTamperingLimit = "anti_tampering_limit"

// CheckAntiTampering denies any access to jev-guard's own configuration, log, or
// session state. It is a hard invariant: it runs before every other check and does
// not depend on fastpath_enabled or user intent. It returns ASK (source
// anti_tampering_limit) when a command is too large to read word by word and its
// text names no protected file. Returns nil when the call is clean.
func CheckAntiTampering(call *harness.NormalizedToolCall) *harness.EvaluationResult {
	if call == nil {
		return nil
	}

	reason := ""
	overLimit := ""
	if session.IsJevguardPath(call.TargetPath) || hasJevguardArg(call) {
		reason = "Direct access to jev-guard security directory or configuration file is prohibited"
	} else if mentionsJevguard(call.Command) {
		reason = "Access to jev-guard configuration or session state via command is prohibited"
	} else if deny, limit := commandWordsMentionJevguard(call); deny {
		reason = "Access to jev-guard configuration or session state via command is prohibited"
	} else if limit != "" {
		overLimit = limit
	} else {
		return nil
	}

	if overLimit != "" {
		return &harness.EvaluationResult{
			Decision:   harness.DecisionAsk,
			Reason:     "Access to jev-guard configuration or session state could not be verified: " + overLimit,
			Source:     SourceAntiTamperingLimit,
			Confidence: 1.0,
		}
	}
	return &harness.EvaluationResult{
		Decision:   harness.DecisionDeny,
		Reason:     reason,
		Source:     "fastpath_tampering",
		Confidence: 1.0,
	}
}

// IsTamperingDenial reports whether an anti-tampering result is a denial, as opposed to nil
// or the ASK given for a command too large to check.
func IsTamperingDenial(result *harness.EvaluationResult) bool {
	return result != nil && result.Decision == harness.DecisionDeny
}

// commandWordsMentionJevguard reads every command in the call the way a shell would (see
// shellWords) and reports whether any word names a protected file once its quotes and escapes
// are removed, so `cat ~/.jev\guard/x` and `cat ~/.jev"guard"/x` are caught. It shares the
// transcript guard's limits; a call over them is reported in limit, never as clean.
func commandWordsMentionJevguard(call *harness.NormalizedToolCall) (deny bool, limit string) {
	seen := map[string]bool{}
	words := 0
	// check reads one command string. It returns true when the command names a protected file.
	check := func(command string) bool {
		if command == "" || seen[command] {
			return false
		}
		seen[command] = true
		if mentionsJevguard(command) {
			return true
		}
		if len(command) > maxGuardCommandBytes {
			if limit == "" {
				limit = "a command is over the limit the check will read"
			}
			return false
		}
		read := shellWords(command)
		words += len(read)
		for _, word := range read {
			if mentionsJevguard(word) {
				return true
			}
		}
		return false
	}

	if check(call.Command) {
		return true, ""
	}
	for _, key := range commandArgKeys {
		raw := call.RawArgs[key]
		if value, ok := raw.(string); ok {
			if check(value) {
				return true, ""
			}
			continue
		}
		// An argument list holds literal words; only a string some program will run is a command.
		list := stringValues(raw)
		size := 0
		for _, word := range list {
			size += len(word)
			if mentionsJevguard(word) {
				return true, ""
			}
		}
		if size > maxGuardCommandBytes {
			if limit == "" {
				limit = "a command is over the limit the check will read"
			}
			continue
		}
		words += len(list)
		for _, payload := range commandPayloads(list) {
			if check(payload) {
				return true, ""
			}
		}
	}
	if limit == "" && words > maxGuardWords {
		limit = "the number of words in a command is over the limit the check will read"
	}
	return false, limit
}

// fileNamePatternArgKeys are arguments that select files by glob rather than by path,
// such as Grep's glob filter or grep_search's Includes. Matched case-insensitively.
var fileNamePatternArgKeys = map[string]bool{"glob": true, "includes": true, "excludes": true}

// hasJevguardArg checks every path-like argument, not just the one chosen as
// TargetPath, so a second path (such as "source" next to "dest") cannot slip through.
// File-name patterns are checked with patternTargetsJevguard, because a glob need not
// name the file exactly.
func hasJevguardArg(call *harness.NormalizedToolCall) bool {
	for _, key := range harness.PathArgKeys {
		for _, value := range stringArgValues(call.RawArgs[key]) {
			if session.IsJevguardPath(value) {
				return true
			}
		}
	}
	tool := strings.ToLower(strings.TrimSpace(call.ToolName))
	for key, raw := range call.RawArgs {
		lowerKey := strings.ToLower(key)
		isPattern := fileNamePatternArgKeys[lowerKey] || (lowerKey == "pattern" && (tool == "glob" || tool == "find_by_name"))
		if !isPattern {
			continue
		}
		for _, value := range stringArgValues(raw) {
			if patternTargetsJevguard(value) {
				return true
			}
		}
	}
	return false
}

func mentionsJevguard(text string) bool {
	lower := strings.ToLower(text)
	return strings.Contains(lower, ".jevguard") || strings.Contains(lower, "jevguard.json")
}

// protectedFileNames are the file and directory names a file-name pattern must not single out.
var protectedFileNames = []string{".jevguard", ".jevguard.json", "jevguard.json", ".jevguard.log"}

// maxPatternExpansions bounds brace expansion of one file-name pattern.
const maxPatternExpansions = 64

// patternTargetsJevguard reports whether a file-name glob singles out a protected file. It
// does when, compared case-insensitively and after brace expansion:
//   - it contains "jevguard" once glob escapes are removed, wildcards or not (*jevguard*.json); or
//   - one of its path segments matches a protected name only because of the letters of
//     "jevguard" (.jev*, *jev?uard*): the same segment does not match that name with
//     "jevguard" replaced by other letters.
//
// A pattern longer than maxPathLikeBytes is denied unread. Broad patterns such as *, **/*,
// .* and *.json match protected files and other files alike, so they are not denied (see the known limits in docs/security-model.md).
func patternTargetsJevguard(pattern string) bool {
	if len(pattern) > maxPathLikeBytes {
		// Longer than any usable path: too large to expand, so it is not a normal file filter.
		return true
	}
	lower := strings.ToLower(pattern)
	expansions, ok := expandBraces(lower, maxPatternExpansions)
	if !ok {
		// Too many alternatives to check: a file filter this large is not a normal search.
		return true
	}
	for _, expanded := range expansions {
		if mentionsJevguardToken(expanded) {
			return true
		}
		// Read backslashes as glob escapes (POSIX, ripgrep) and as Windows separators.
		for _, reading := range []string{expanded, strings.ReplaceAll(expanded, `\`, "/")} {
			for _, segment := range strings.Split(reading, "/") {
				if segmentSinglesOutProtected(segment) {
					return true
				}
			}
		}
	}
	return false
}

// mentionsJevguardToken reports whether text holds the distinctive token "jevguard" once
// glob escapes and character-class brackets are removed.
func mentionsJevguardToken(text string) bool {
	stripped := strings.NewReplacer(`\`, "", "[", "", "]", "").Replace(text)
	return strings.Contains(stripped, "jevguard")
}

func segmentSinglesOutProtected(segment string) bool {
	if !strings.ContainsAny(segment, "*?[") {
		return false
	}
	for _, name := range protectedFileNames {
		if matched, err := path.Match(segment, name); err != nil || !matched {
			continue
		}
		control := strings.Replace(name, "jevguard", "qqqqqqqq", 1)
		if matched, err := path.Match(segment, control); err == nil && !matched {
			return true
		}
	}
	return false
}

// expandBraces expands {a,b} alternatives the way glob libraries do, including nested ones.
// It reports false when the expansion would exceed limit.
func expandBraces(pattern string, limit int) ([]string, bool) {
	open, close, commas := findBraceGroup(pattern)
	if open < 0 {
		return []string{pattern}, true
	}
	prefix, suffix := pattern[:open], pattern[close+1:]
	var out []string
	start := open + 1
	for _, end := range append(commas, close) {
		rest, ok := expandBraces(prefix+pattern[start:end]+suffix, limit-len(out))
		if !ok {
			return nil, false
		}
		out = append(out, rest...)
		if len(out) > limit {
			return nil, false
		}
		start = end + 1
	}
	return out, true
}

// findBraceGroup finds the first unescaped {...} group with a top-level comma and returns
// the positions of its braces and commas, or -1 when there is none.
func findBraceGroup(s string) (int, int, []int) {
	for open := 0; open < len(s); open++ {
		if s[open] == '\\' {
			open++
			continue
		}
		if s[open] != '{' {
			continue
		}
		depth := 0
		var commas []int
		for i := open; i < len(s); i++ {
			switch s[i] {
			case '\\':
				i++
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					if len(commas) > 0 {
						return open, i, commas
					}
					i = len(s)
				}
			case ',':
				if depth == 1 {
					commas = append(commas, i)
				}
			}
		}
	}
	return -1, -1, nil
}

// stringArgValues returns the string values of a raw argument: the value itself, or
// the string elements of a list.
func stringArgValues(raw interface{}) []string {
	switch v := raw.(type) {
	case string:
		return []string{v}
	case []interface{}:
		var out []string
		for _, item := range v {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
		return out
	case []string:
		return v
	}
	return nil
}
