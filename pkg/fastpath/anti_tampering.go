package fastpath

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
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
	if session.IsJevguardPath(call.TargetPath) || hasJevguardArg(call) || patchTargetsJevguard(call) {
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

// maxTamperingPathLookups bounds the path-like command words resolved against the security
// directory per call, because each resolution reads the filesystem.
const maxTamperingPathLookups = 2048

// commandWordsMentionJevguard reads every command in the call the way a shell would (see
// shellWords) and reports whether any word names a protected file once its quotes and escapes
// are removed, so `cat ~/.jev\guard/x` and `cat ~/.jev"guard"/x` are caught. It also denies:
//   - a path-like word that resolves into the security directory, which may be a custom
//     JEV_GUARD_HOME whose name says nothing (see wordReachesJevguard); and
//   - a glob or brace pattern that singles out a protected name, such as ~/.jev*/state or
//     ~/.{jev,x}guard/state (see patternTargetsJevguard).
//
// All commands of a call share one shell-reading budget and the transcript guard's limits; a
// call over them is reported in limit, never as clean. A denial found before the budget ran
// out still counts.
func commandWordsMentionJevguard(call *harness.NormalizedToolCall) (deny bool, limit string) {
	c := &commandCheck{reader: newShellReader(), dirs: callWorkingDirs(call), resolved: map[string]bool{}}
	if home, err := os.UserHomeDir(); err == nil {
		c.home = home
	}
	words := 0
	seen := map[string]bool{}
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
			c.exceed("a command is over the limit the check will read")
			return false
		}
		read, patterns := c.reader.read(command, false)
		words += len(read)
		return c.wordsTargetJevguard(read, patterns)
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
		// Its words are not globbed by a shell, so they are checked as paths only.
		list := stringValues(raw)
		size := 0
		for _, word := range list {
			size += len(word)
			if mentionsJevguard(word) {
				return true, ""
			}
		}
		if size > maxGuardCommandBytes {
			c.exceed("a command is over the limit the check will read")
			continue
		}
		words += len(list)
		if c.wordsTargetJevguard(list, nil) {
			return true, ""
		}
		for _, payload := range c.reader.commandPayloads(list) {
			if check(payload) {
				return true, ""
			}
		}
	}
	if c.reader.exhausted {
		c.exceed("a command needs more work to read than the check will do")
	}
	if words > maxGuardWords {
		c.exceed("the number of words in a command is over the limit the check will read")
	}
	return false, c.limit
}

// commandCheck holds one call's state while its command words are checked.
type commandCheck struct {
	reader   *shellReader
	dirs     []string // working directories relative paths are resolved against
	home     string
	resolved map[string]bool
	limit    string
}

func (c *commandCheck) exceed(limit string) {
	if c.limit == "" {
		c.limit = limit
	}
}

func (c *commandCheck) wordsTargetJevguard(words, patterns []string) bool {
	for _, word := range words {
		if mentionsJevguard(word) || c.wordReachesJevguard(word) {
			return true
		}
	}
	for _, pattern := range patterns {
		if c.shellPatternTargetsJevguard(pattern) {
			return true
		}
	}
	return false
}

// wordReachesJevguard reports whether a path-like word (one holding a separator or starting
// with a home or variable spelling) points into the security directory, as written, with the
// home directory and the hook's environment variables expanded, and resolved against each
// working directory. session.IsJevguardPath compares it with the configured directory, so a
// custom JEV_GUARD_HOME is protected under any spelling that reaches it, including symlinks.
func (c *commandCheck) wordReachesJevguard(word string) bool {
	if word == "" || len(word) > maxPathLikeBytes || !strings.ContainsAny(word, `/\~$%`) {
		return false
	}
	candidates := []string{word}
	if expanded := expandHomeWith(word, c.home); expanded != word {
		candidates = append(candidates, expanded)
	}
	if strings.ContainsRune(word, '$') {
		candidates = append(candidates, os.ExpandEnv(word))
	}
	for _, candidate := range candidates {
		forms := []string{candidate}
		if !filepath.IsAbs(candidate) && !strings.HasPrefix(candidate, "~") && len(c.dirs) > 0 {
			forms = forms[:0]
			for _, dir := range c.dirs {
				forms = append(forms, filepath.Join(dir, candidate))
			}
		}
		for _, form := range forms {
			if form == "" || c.resolved[form] {
				continue
			}
			if len(c.resolved) >= maxTamperingPathLookups {
				c.exceed("the number of paths in a command is over the limit the check will resolve")
				return false
			}
			c.resolved[form] = true
			if mentionsJevguard(form) || session.IsJevguardPath(form) {
				return true
			}
		}
	}
	return false
}

// shellPatternTargetsJevguard checks a glob or brace pattern from a command (see
// shellReader.read) and each part of it between shell operators, with Bash's {a..z} sequences
// and [!...] classes rewritten for patternTargetsJevguard. A pattern too large to expand is
// reported as over the limit rather than denied, since a command word need not be a filter.
func (c *commandCheck) shellPatternTargetsJevguard(pattern string) bool {
	expanded := strings.ReplaceAll(expandBraceSequences(pattern), "[!", "[^")
	parts := append([]string{expanded}, strings.FieldsFunc(expanded, func(r rune) bool { return strings.ContainsRune(";|&<>()`=:", r) })...)
	for _, part := range parts {
		targets, ok := patternCheck(part)
		if targets {
			return true
		}
		if !ok {
			c.exceed("a glob pattern in a command is over the limit the check will read")
		}
	}
	return false
}

// braceSequence matches Bash's {x..y} and {x..y..step} sequence expressions.
var braceSequence = regexp.MustCompile(`\{(-?[0-9]+|[A-Za-z])\.\.(-?[0-9]+|[A-Za-z])(?:\.\.-?[0-9]+)?\}`)

// expandBraceSequences rewrites each {x..y} letter sequence as the {a,b,...} alternatives it
// stands for (stepping by one, which covers every element a larger step could produce), so
// that expandBraces sees them. A letter sequence has at most 58 elements. A number sequence
// is replaced by its first number: no protected name holds a digit, so every element matches
// the same protected names.
func expandBraceSequences(pattern string) string {
	return braceSequence.ReplaceAllStringFunc(pattern, func(match string) string {
		groups := braceSequence.FindStringSubmatch(match)
		_, fromErr := strconv.Atoi(groups[1])
		_, toErr := strconv.Atoi(groups[2])
		switch {
		case fromErr == nil && toErr == nil:
			return groups[1]
		case fromErr == nil || toErr == nil:
			return match // mixed: Bash leaves it unexpanded
		}
		from, to := groups[1][0], groups[2][0]
		if from > to {
			from, to = to, from
		}
		var elements []string
		for b := from; b <= to; b++ {
			element := string(rune(b))
			if strings.IndexByte(patternMeta+"^", b) >= 0 {
				element = `\` + element
			}
			elements = append(elements, element)
		}
		if len(elements) == 1 {
			return elements[0]
		}
		return "{" + strings.Join(elements, ",") + "}"
	})
}

// patchTargetsJevguard reports whether an apply_patch body in any argument adds, updates,
// deletes or moves a file into the security directory. Relative headers are resolved against
// each working directory.
func patchTargetsJevguard(call *harness.NormalizedToolCall) bool {
	dirs := callWorkingDirs(call)
	for _, text := range append(allStrings(call.RawArgs), call.Command) {
		if !strings.Contains(text, "*** ") {
			continue
		}
		for _, match := range patchFileHeader.FindAllStringSubmatch(text, -1) {
			target := strings.TrimSpace(match[1])
			if target == "" {
				continue
			}
			if mentionsJevguard(target) || session.IsJevguardPath(target) {
				return true
			}
			if filepath.IsAbs(target) || strings.HasPrefix(target, "~") {
				continue
			}
			for _, dir := range dirs {
				if session.IsJevguardPath(filepath.Join(dir, target)) {
					return true
				}
			}
		}
	}
	return false
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
	targets, ok := patternCheck(pattern)
	// A pattern too large to check is not a normal file filter.
	return targets || !ok
}

// patternCheck is patternTargetsJevguard that reports a pattern too large to check (longer than
// maxPathLikeBytes, or with more than maxPatternExpansions brace alternatives) as not ok.
func patternCheck(pattern string) (targets, ok bool) {
	if len(pattern) > maxPathLikeBytes {
		return false, false
	}
	lower := strings.ToLower(pattern)
	expansions, ok := expandBraces(lower, maxPatternExpansions)
	if !ok {
		return false, false
	}
	for _, expanded := range expansions {
		if mentionsJevguardToken(expanded) {
			return true, true
		}
		// Read backslashes as glob escapes (POSIX, ripgrep) and as Windows separators.
		for _, reading := range []string{expanded, strings.ReplaceAll(expanded, `\`, "/")} {
			for _, segment := range strings.Split(reading, "/") {
				if segmentSinglesOutProtected(segment) {
					return true, true
				}
			}
		}
	}
	return false, true
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
