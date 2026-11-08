package fastpath

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"unicode/utf16"

	"jev-guard/pkg/boundary"
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
	// One resolution scope for every path checked below: they share the per-call work budget
	// and the prefix cache (joins the caller's scope when there is one).
	defer boundary.BeginEvaluation()()

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

// maxTamperingPathLookups bounds the distinct command-word paths resolved against the security
// directory per call. The boundary evaluation's work budget bounds the bytes the lookups walk
// (deep working directories); this bounds their number, since each costs a system call even
// on a short path (tens of microseconds on Windows). It is well above the operand count of an
// ordinary command, bare file names included.
const maxTamperingPathLookups = 8192

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
	if reason := c.reader.incomplete(); reason != "" {
		c.exceed(reason)
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

	securityDirs     [][]string // the security directory's components, as configured and resolved
	securityDirsRead bool

	securityHome     string // the security directory, canonicalized once (isSecurityPath)
	securityHomeErr  error
	securityHomeRead bool
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

// wordReachesJevguard is pathReachesJevguard for a word the reader returned. Its variables are
// filled in only when a shell would expand them (see shellReader.expands): '$X/state' is a
// literal name in every shell, and so is a word of an argument list.
func (c *commandCheck) wordReachesJevguard(word string) bool {
	return c.pathReachesJevguard(word, c.reader.expands[word])
}

// pathReachesJevguard reports whether a word points into the security directory, as written,
// with a leading ~ expanded, with the home directory's other spellings and the hook's
// environment variables filled in when expand is set, and resolved against each working
// directory. A path-like word (one holding a separator or starting with a home or variable
// spelling) is checked as written; a bare word such as "alias" or "state" is checked only
// against the working directories, since that is where a command would open it, so a bare
// symlink into the security directory, or a plain file name while the working directory is
// inside it, is caught. Option-like words are resolved as well, since after "--" they are
// file operands.
//
// The configured directory is compared with by session.IsJevguardPathIn, so a custom
// JEV_GUARD_HOME is protected under any spelling that reaches it, including symlinks. A
// leading ~ is expanded even when quoted, because PowerShell's file system provider expands
// it itself. Every resolution draws on the call's boundary evaluation scope (see
// CheckAntiTampering): words under one working directory share its resolved prefix, and a
// path that cannot be resolved within the scope's budget or the path length limit is
// reported through exceed (the ASK floor), not as clean.
func (c *commandCheck) pathReachesJevguard(word string, expand bool) bool {
	if word == "" || len(word) > maxPathLikeBytes {
		return false
	}
	bare := !strings.ContainsAny(word, `/\~$%`)
	// Option-like words ("-x", "--name") are resolved too: after "--" they are file operands,
	// and resolving a flag against the cached working directory costs one lookup.
	if bare && len(c.dirs) == 0 {
		return false
	}
	candidates := []string{word}
	if !bare && (expand || strings.HasPrefix(word, "~")) {
		if expanded := expandHomeWith(word, c.home); expanded != word {
			candidates = append(candidates, expanded)
		}
	}
	if !bare && expand && strings.ContainsRune(word, '$') {
		candidates = append(candidates, os.ExpandEnv(word))
	}
	for _, candidate := range candidates {
		forms := []string{candidate}
		if !filepath.IsAbs(candidate) && !strings.HasPrefix(candidate, "~") && len(c.dirs) > 0 {
			forms = forms[:0]
			for _, dir := range c.dirs {
				forms = append(forms, boundary.JoinPath(dir, candidate))
			}
		}
		for _, form := range forms {
			if form == "" || c.resolved[form] {
				continue
			}
			if mentionsJevguard(form) {
				return true
			}
			if hasOverlongComponent(form) {
				continue
			}
			if len(c.resolved) >= maxTamperingPathLookups {
				c.exceed("the number of paths in a command is over the limit the check will resolve")
				return false
			}
			c.resolved[form] = true
			if c.isSecurityPath(form) {
				return true
			}
		}
	}
	return false
}

// maxNameLength is the longest file name (one path component) the OS accepts on Linux
// (NAME_MAX, 255 bytes) and Windows (255 UTF-16 code units).
const maxNameLength = 255

// maxNameBytesElsewhere bounds a file name on other systems. macOS HFS+ counts 255 UTF-16
// units and APFS 255 characters, so a valid name can be longer than 255 bytes; no name of
// 255 characters exceeds 4 bytes per character.
const maxNameBytesElsewhere = 4 * maxNameLength

// hasOverlongComponent reports whether a component of path is longer than any file name can
// be on this OS. No file has such a name, so the OS fails to open the path (ENAMETOOLONG) and
// there is nothing to protect. Such words are common in commands that are not paths at all (a
// long quoted string holding a backslash), and resolving them would fail with a resolution
// limit. On systems other than Linux and Windows only components no file system can hold are
// skipped, so a long multibyte name that macOS accepts is still resolved.
func hasOverlongComponent(path string) bool {
	start := 0
	for i := 0; i <= len(path); i++ {
		if i == len(path) || os.IsPathSeparator(path[i]) {
			if componentTooLong(path[start:i]) {
				return true
			}
			start = i + 1
		}
	}
	return false
}

func componentTooLong(name string) bool {
	return componentTooLongFor(runtime.GOOS, name)
}

func componentTooLongFor(goos, name string) bool {
	switch goos {
	case "linux":
		return len(name) > maxNameLength
	case "windows":
		return len(name) > maxNameLength && len(utf16.Encode([]rune(name))) > maxNameLength
	default:
		return len(name) > maxNameBytesElsewhere
	}
}

// readSecurityHome canonicalizes the security directory once per call.
func (c *commandCheck) readSecurityHome() {
	if !c.securityHomeRead {
		c.securityHomeRead = true
		c.securityHome, c.securityHomeErr = session.CanonicalJevguardDir()
	}
}

// isSecurityPath reports whether path resolves into the security directory. The directory is
// canonicalized once per call. A resolution limit (boundary.ErrResolutionLimit) is recorded
// as the ASK floor and reported as false: a command word is only a guess at a path, so an
// over-long or over-budget word is not proof of tampering, and the stages after
// anti-tampering, which share the exhausted budget, fail closed as well.
func (c *commandCheck) isSecurityPath(path string) bool {
	c.readSecurityHome()
	if c.securityHomeErr != nil {
		c.exceed("the security directory could not be resolved: " + c.securityHomeErr.Error())
		return false
	}
	in, err := session.IsJevguardPathIn(c.securityHome, path)
	if err != nil {
		c.exceed("a path in a command could not be resolved: " + err.Error())
		return false
	}
	return in
}

// shellPatternTargetsJevguard checks a glob or brace pattern from a command (see
// shellReader.read) and each part of it between shell operators, with Bash's {a..z} sequences
// and [!...] classes rewritten. Each part is denied when:
//   - it singles out a protected file name (patternCheck); or
//   - one of its brace alternatives without wildcards is a path into the security directory
//     (pathReachesJevguard); or
//   - one of its alternatives with wildcards singles out the configured security directory
//     (patternSinglesOutSecurityDir), so a custom JEV_GUARD_HOME whose name says nothing is
//     protected from /srv/guard-hom?/state and /srv/guard-{home,x}/state too.
//
// The variables a shell would expand in it are filled in from the hook's environment. A
// pattern too large to expand is reported as over the limit rather than denied, since a
// command word need not be a filter.
func (c *commandCheck) shellPatternTargetsJevguard(pattern string) bool {
	expanded := strings.ReplaceAll(expandBraceSequences(expandPatternVariables(pattern)), "[!", "[^")
	parts := append([]string{expanded}, strings.FieldsFunc(expanded, func(r rune) bool { return strings.ContainsRune(";|&<>()`=:", r) })...)
	for _, part := range parts {
		targets, ok := patternCheck(part)
		if targets {
			return true
		}
		alternatives, expandedOK := expandBraces(part, maxPatternExpansions)
		if !ok || !expandedOK {
			c.exceed("a glob pattern in a command is over the limit the check will read")
			continue
		}
		for _, alternative := range alternatives {
			if !hasGlobMeta(alternative) {
				if c.pathReachesJevguard(unescapePattern(alternative), false) {
					return true
				}
				continue
			}
			if c.patternSinglesOutSecurityDir(alternative) {
				return true
			}
		}
	}
	return false
}

// expandPatternVariables fills in the unescaped $NAME and ${NAME} references in a pattern from
// the hook's environment, escaping wildcards in their values. A $ that was quoted literally is
// escaped in the pattern (see wordBuilder.writeByte), so it stays as written.
func expandPatternVariables(pattern string) string {
	if !strings.ContainsRune(pattern, '$') {
		return pattern
	}
	var out strings.Builder
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if c == '\\' && i+1 < len(pattern) {
			out.WriteString(pattern[i : i+2])
			i++
			continue
		}
		if c != '$' || i+1 >= len(pattern) {
			out.WriteByte(c)
			continue
		}
		name, end := "", i+1
		if pattern[end] == '{' {
			close := strings.IndexByte(pattern[end:], '}')
			if close < 0 {
				out.WriteByte(c)
				continue
			}
			name, end = pattern[end+1:end+close], end+close+1
		} else {
			for end < len(pattern) && (pattern[end] == '_' || isAlphaNumeric(pattern[end])) {
				end++
			}
			name = pattern[i+1 : end]
		}
		if name == "" {
			out.WriteByte(c)
			continue
		}
		out.WriteString(escapePattern(filepath.ToSlash(os.Getenv(name))))
		i = end - 1
	}
	return out.String()
}

func isAlphaNumeric(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// escapePattern escapes the characters of a literal path that a pattern would read as wildcards.
func escapePattern(literal string) string {
	var out strings.Builder
	for i := 0; i < len(literal); i++ {
		if literal[i] == '$' || strings.IndexByte(patternMeta, literal[i]) >= 0 {
			out.WriteByte('\\')
		}
		out.WriteByte(literal[i])
	}
	return out.String()
}

// unescapePattern removes a pattern's escapes, giving the literal path it names.
func unescapePattern(pattern string) string {
	if !strings.ContainsRune(pattern, '\\') {
		return pattern
	}
	var out strings.Builder
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == '\\' && i+1 < len(pattern) {
			i++
		}
		out.WriteByte(pattern[i])
	}
	return out.String()
}

// hasGlobMeta reports whether a pattern holds an unescaped *, ? or [.
func hasGlobMeta(pattern string) bool {
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			i++
		case '*', '?', '[':
			return true
		}
	}
	return false
}

// securityDirComponents returns the security directory's path components, as configured and
// as the filesystem resolves it, lower-cased. They are computed once per call.
func (c *commandCheck) securityDirComponents() [][]string {
	if c.securityDirsRead {
		return c.securityDirs
	}
	c.securityDirsRead = true
	dirs := []string{session.GetJevguardDir()}
	if c.readSecurityHome(); c.securityHomeErr == nil && c.securityHome != dirs[0] {
		dirs = append(dirs, c.securityHome)
	}
	for _, dir := range dirs {
		if components := pathComponents(strings.ToLower(filepath.ToSlash(dir))); len(components) > 0 {
			c.securityDirs = append(c.securityDirs, components)
		}
	}
	return c.securityDirs
}

// pathComponents splits a cleaned slash path into its components; an absolute path's first
// component is "" (or a drive such as "c:").
func pathComponents(p string) []string {
	p = path.Clean(p)
	if p == "/" || p == "." {
		return nil
	}
	return strings.Split(p, "/")
}

// patternSinglesOutSecurityDir reports whether a glob pattern reaches the security directory
// or a file in it, and the pattern component that matches the directory's own name singles it
// out: it is written out, or it is a wildcard that would not match the name with its letters
// and digits replaced (secure-stor?, sec*, but not * or .*). Broad patterns such as /srv/* and
// ~/.*/state are allowed, as for protected file names. Relative patterns are read against each
// working directory, a leading ~ is expanded, and a backslash is read both as an escape and as
// a Windows separator. Comparison ignores case. Symlinks inside the pattern are not followed.
func (c *commandCheck) patternSinglesOutSecurityDir(pattern string) bool {
	dirs := c.securityDirComponents()
	if len(dirs) == 0 {
		return false
	}
	lower := strings.ToLower(pattern)
	for _, reading := range []string{lower, strings.ReplaceAll(lower, `\`, "/")} {
		var absolute []string
		switch {
		case strings.HasPrefix(reading, "~"):
			if c.home != "" && (reading == "~" || reading[1] == '/') {
				absolute = append(absolute, escapePattern(strings.ToLower(filepath.ToSlash(c.home)))+reading[1:])
			}
		case strings.HasPrefix(reading, "/") || (len(reading) > 1 && reading[1] == ':'):
			absolute = append(absolute, reading)
		default:
			for _, dir := range c.dirs {
				absolute = append(absolute, escapePattern(strings.ToLower(filepath.ToSlash(dir)))+"/"+reading)
			}
		}
		for _, candidate := range absolute {
			components := pathComponents(candidate)
			for _, dir := range dirs {
				if componentsSingleOut(components, dir) {
					return true
				}
			}
		}
	}
	return false
}

// componentsSingleOut matches pattern components against a directory's components, reading **
// as any number of components. It reports whether some match covers the whole directory and
// matches its last component with a component that singles it out (see
// patternSinglesOutSecurityDir). It works in time proportional to the product of the lengths.
func componentsSingleOut(pattern, dir []string) bool {
	last := len(dir) - 1
	// reach[i][j]: pattern[:i] can match dir[:j], for j up to the directory's parent.
	reach := make([][]bool, len(pattern)+1)
	for i := range reach {
		reach[i] = make([]bool, last+1)
	}
	reach[0][0] = true
	for j := 0; j <= last; j++ {
		for i := 0; i <= len(pattern); i++ {
			if !reach[i][j] || i == len(pattern) {
				continue
			}
			if pattern[i] == "**" {
				reach[i+1][j] = true // ** matching no component
				if j < last {
					reach[i][j+1] = true
				}
				continue
			}
			if j < last && componentMatches(pattern[i], dir[j]) {
				reach[i+1][j+1] = true
			}
		}
	}
	for i := 0; i < len(pattern); i++ {
		if reach[i][last] && pattern[i] != "**" && componentMatches(pattern[i], dir[last]) && componentSinglesOut(pattern[i], dir[last]) {
			return true
		}
	}
	return false
}

func componentMatches(pattern, name string) bool {
	matched, err := path.Match(pattern, name)
	return err == nil && matched
}

// componentSinglesOut reports whether a pattern component that matches name is specific to it:
// it is not a wildcard, or it does not match name with every letter and digit replaced.
func componentSinglesOut(pattern, name string) bool {
	if !hasGlobMeta(pattern) {
		return true
	}
	control := []byte(name)
	for i, b := range control {
		if isAlphaNumeric(b) {
			control[i] = 'q'
			if b == 'q' {
				control[i] = 'z'
			}
		}
	}
	return !componentMatches(pattern, string(control))
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
				if session.IsJevguardPath(boundary.JoinPath(dir, target)) {
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
