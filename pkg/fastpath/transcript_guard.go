package fastpath

import (
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"jev-guard/pkg/harness"
)

// The guard's work budget, per tool call. It is sized so a call that fits finishes well under
// a second. A call over budget gets an explicit ASK, which audit mode reports like any verdict.
const (
	maxGuardCommandBytes = 2 << 20 // of one command
	maxGuardPathBytes    = 1 << 20 // of one path input
	maxGuardWords        = 50_000  // distinct words and word parts of all commands in a call
	maxGuardComponents   = 1_000_000
	maxGuardLookups      = 60_000 // filesystem calls, which are the slow part on Windows
	maxSymlinkHops       = 64     // per path; a chain this long fails in the OS too
	maxGuardHops         = 10_000
)

// maxPathLikeBytes is longer than any usable path, so a longer argument is treated as content.
const maxPathLikeBytes = 4096

// lookupCacheBytes keeps the per-call cache small on hostile input: only short paths are kept.
const lookupCacheBytes = 512

// sourceTranscriptGuardLimit is reported when a call is too large to check.
const sourceTranscriptGuardLimit = "transcript_guard_limit"

// commandArgKeys hold commands, as a string or as an argument list.
var commandArgKeys = []string{"CommandLine", "command", "cmd", "script"}

// patchFileHeader finds the files an apply_patch body names.
var patchFileHeader = regexp.MustCompile(`(?m)^\*\*\* (?:Add File|Update File|Delete File|Move to): (.*)$`)

// homePrefixes are spellings of the home directory that a tool or shell expands itself.
var homePrefixes = []string{"~", "$HOME", "${HOME}", "$env:HOME", "$env:USERPROFILE", "%USERPROFILE%", "%HOME%"}

// msysDrivePath matches how Git Bash and MSYS spell a Windows drive: /c/Users/x.
var msysDrivePath = regexp.MustCompile(`^/([a-zA-Z])(/.*)?$`)

// CheckTranscriptTampering protects the transcript that Antigravity prompt intent is read
// from: an agent that could write it could forge the user's authorization. It denies access
// and asks when a call is too large to check. Callers run it only when the user opted in to
// transcript intent; it has no cost otherwise. Returns nil when the call is clean.
func CheckTranscriptTampering(call *harness.NormalizedToolCall) *harness.EvaluationResult {
	if call == nil {
		return nil
	}
	guard := &transcriptGuard{lookups: map[string]lookupResult{}}
	if reason := guard.check(call); reason != "" {
		return &harness.EvaluationResult{
			Decision:   harness.DecisionDeny,
			Reason:     reason,
			Source:     "fastpath_tampering",
			Confidence: 1.0,
		}
	}
	if guard.overBudget != "" {
		return &harness.EvaluationResult{
			Decision:   harness.DecisionAsk,
			Reason:     "Access to the Antigravity transcript could not be verified: " + guard.overBudget,
			Source:     sourceTranscriptGuardLimit,
			Confidence: 1.0,
		}
	}
	return nil
}

type lookupResult struct {
	mode os.FileMode
	err  error
}

// transcriptGuard holds one call's work budget. Once overBudget is set, checks stop.
type transcriptGuard struct {
	overBudget string
	components int
	hops       int
	lookupRuns int
	lookups    map[string]lookupResult
}

func (g *transcriptGuard) exceed(what string) {
	if g.overBudget == "" {
		g.overBudget = what + " is over the limit the guard will check"
	}
}

// check runs every path input through the matcher, as written and as the filesystem would
// resolve it, so a symlink cannot hide the transcript. Inputs are resolved from their exact
// bytes; any trimmed or decoded form is checked in addition, never instead. A path computed
// when a shell command runs is out of reach here (see the limits in docs/security-model.md).
func (g *transcriptGuard) check(call *harness.NormalizedToolCall) string {
	const directReason = "Direct access to Antigravity conversation transcript/system state is prohibited"
	const commandReason = "Access to Antigravity conversation transcript/system state via command is prohibited"

	dirs := callWorkingDirs(call)
	targets := append([]string{call.TargetPath}, dirs...)
	for _, key := range harness.PathArgKeys {
		targets = append(targets, stringValues(call.RawArgs[key])...)
	}
	args := allStrings(call.RawArgs)
	for _, text := range append(args, call.Command) {
		for _, match := range patchFileHeader.FindAllStringSubmatch(text, -1) {
			targets = append(targets, match[1])
		}
	}
	for _, target := range targets {
		if len(target) > maxGuardPathBytes {
			g.exceed("a path")
			return ""
		}
		for _, form := range g.pathForms(target, dirs) {
			if isAntigravitySystemPath(form, "") {
				return directReason
			}
		}
		if g.overBudget != "" {
			return ""
		}
	}

	// Any other argument may be a path under a name we do not know, or just text that
	// mentions one. It only counts when it is one line and leads somewhere real.
	for _, value := range args {
		if len(value) > maxPathLikeBytes || strings.ContainsAny(value, "\r\n") {
			continue
		}
		for _, form := range g.pathForms(value, dirs) {
			if isAntigravitySystemPath(form, "") && parentExists(form) {
				return directReason
			}
		}
		if g.overBudget != "" {
			return ""
		}
	}

	var words, textWords []string
	reader := newShellReader()
	seenCommands := map[string]bool{}
	addCommand := func(command string) bool {
		if command == "" || seenCommands[command] {
			return true
		}
		seenCommands[command] = true
		// Matched broadly on purpose: shell globs and variables
		// (e.g. ~/.gemini/antigravity/brain/*/.sys*/logs/t*) cannot be parsed reliably.
		if namesTranscriptInText(command) {
			return false
		}
		if len(command) > maxGuardCommandBytes {
			g.exceed("a command")
			return true
		}
		read, _ := reader.read(command, false)
		words = append(words, read...)
		// What a heredoc holds is data, so the spelled-out-name rule does not read it.
		read, _ = reader.read(command, true)
		textWords = append(textWords, read...)
		if reader.exhausted {
			g.exceed("a command")
		}
		return true
	}
	if !addCommand(call.Command) {
		return commandReason
	}
	for _, key := range commandArgKeys {
		raw := call.RawArgs[key]
		if value, ok := raw.(string); ok {
			if !addCommand(value) {
				return commandReason
			}
			continue
		}
		// An argument list holds literal words, so only a string some program will run is a command.
		list := stringValues(raw)
		size := 0
		for _, word := range list {
			size += len(word)
		}
		if size > maxGuardCommandBytes {
			g.exceed("a command")
			return ""
		}
		words = append(words, list...)
		textWords = append(textWords, list...)
		for _, payload := range reader.commandPayloads(list) {
			if !addCommand(payload) {
				return commandReason
			}
		}
		if reader.exhausted {
			g.exceed("a command")
		}
	}
	if g.overBudget != "" {
		return ""
	}
	if len(words) > maxGuardWords || len(textWords) > maxGuardWords {
		g.exceed("the number of words in a command")
		return ""
	}
	for _, word := range textWords {
		if namesTranscriptInText(word) {
			return commandReason
		}
	}
	for _, word := range words {
		// A word that resolves anywhere under the brain directory gets the same answer as
		// spelling that path out, so a link to a conversation directory cannot be moved or replaced.
		for _, form := range g.pathForms(word, dirs) {
			if strings.Contains(strings.ToLower(normalizePathSeparators(form)), "/.gemini/antigravity/brain") {
				return commandReason
			}
		}
		if g.overBudget != "" {
			return ""
		}
	}
	return ""
}

func namesTranscriptInText(text string) bool {
	lower := strings.ToLower(normalizePathSeparators(text))
	return strings.Contains(lower, "antigravity/brain") || strings.Contains(lower, ".system_generated") || strings.Contains(lower, "transcript.jsonl")
}

func parentExists(form string) bool {
	_, err := os.Lstat(filepath.Dir(form))
	return err == nil
}

// callWorkingDirs returns the directories relative paths may be resolved against: the
// normalized one and any other working-directory argument, which the tool may honor instead.
// Exact values come first; a value that differs when trimmed is also listed trimmed.
// A name made only of whitespace is a valid directory; only an empty value is skipped.
func callWorkingDirs(call *harness.NormalizedToolCall) []string {
	var dirs []string
	add := func(dir string) {
		if dir == "" {
			return
		}
		for _, d := range dirs {
			if d == dir {
				return
			}
		}
		dirs = append(dirs, dir)
	}
	add(call.Cwd)
	add(strings.TrimSpace(call.Cwd))
	bases := append([]string(nil), dirs...)
	for _, key := range harness.CwdArgKeys {
		for _, value := range stringValues(call.RawArgs[key]) {
			for _, form := range []string{value, strings.TrimSpace(value)} {
				if form == "" {
					continue
				}
				if filepath.IsAbs(form) || len(bases) == 0 {
					add(form)
					continue
				}
				for _, base := range bases {
					add(base + string(filepath.Separator) + form)
				}
			}
		}
	}
	return dirs
}

// allStrings returns every string inside a tool's arguments, at any depth.
func allStrings(raw interface{}) []string {
	switch v := raw.(type) {
	case string:
		return []string{v}
	case []string:
		return v
	case []interface{}:
		var out []string
		for _, item := range v {
			out = append(out, allStrings(item)...)
		}
		return out
	case map[string]interface{}:
		var out []string
		for _, item := range v {
			out = append(out, allStrings(item)...)
		}
		return out
	}
	return nil
}

func stringValues(raw interface{}) []string {
	switch v := raw.(type) {
	case string:
		return []string{v}
	case []string:
		return v
	case []interface{}:
		var out []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// pathVariants returns p's exact bytes first, then any other spelling a tool or shell may
// mean by it. Each is an addition: a form never replaces the one it came from.
func pathVariants(p string) []string {
	variants := []string{p}
	add := func(v string) {
		for _, existing := range variants {
			if existing == v {
				return
			}
		}
		if v != "" {
			variants = append(variants, v)
		}
	}
	add(strings.TrimSpace(p))
	for _, v := range append([]string(nil), variants...) {
		if rest, ok := fileURIPath(v); ok {
			add(rest)
			if decoded, err := url.PathUnescape(rest); err == nil {
				add(decoded)
			}
		}
	}
	for _, v := range append([]string(nil), variants...) {
		add(expandHome(v))
	}
	if runtime.GOOS == "windows" {
		for _, v := range append([]string(nil), variants...) {
			add(windowsDriveFromMSYS(v))
		}
	}
	return variants
}

// windowsDriveFromMSYS turns Git Bash's /c/Users/x into c:/Users/x. Returns "" for anything else.
func windowsDriveFromMSYS(p string) string {
	match := msysDrivePath.FindStringSubmatch(p)
	if match == nil {
		return ""
	}
	return match[1] + ":" + match[2]
}

// fileURIPath returns the path of a file: URI, in any of the spellings tools accept.
func fileURIPath(p string) (string, bool) {
	lower := strings.ToLower(p)
	switch {
	case strings.HasPrefix(lower, "file://localhost/"):
		return p[len("file://localhost"):], true
	case isFileURI(p):
		return extractFilePathFromURI(p), true
	case strings.HasPrefix(lower, "file:"):
		return p[len("file:"):], true
	}
	return "", false
}

// pathForms returns p in every spelling, as written and resolved against each working
// directory, without requiring it to exist. Only an empty p is skipped: a name made of
// whitespace is valid, and is resolved from its exact bytes.
func (g *transcriptGuard) pathForms(p string, dirs []string) []string {
	if p == "" {
		return nil
	}
	if len(dirs) == 0 {
		dirs = []string{""}
	}
	var forms []string
	for _, dir := range dirs {
		for _, variant := range pathVariants(p) {
			forms = append(forms, variant)
			candidates := []string{variant}
			if strings.ContainsRune(variant, '$') {
				candidates = append(candidates, expandVariables(variant, dir))
			}
			for _, candidate := range candidates {
				if !filepath.IsAbs(candidate) && dir != "" {
					// Deliberately not filepath.Join, which would remove ".." before symlinks are seen.
					candidate = dir + string(filepath.Separator) + candidate
					forms = append(forms, normalizePathSeparators(candidate))
				}
				forms = append(forms, g.resolvedForms(candidate)...)
			}
		}
	}
	return forms
}

// expandVariables applies the hook's environment, which approximates the shell's.
func expandVariables(p, dir string) string {
	return os.Expand(p, func(name string) string {
		if name == "PWD" && dir != "" {
			return dir
		}
		return os.Getenv(name)
	})
}

func (g *transcriptGuard) resolvedForms(p string) []string {
	if !filepath.IsAbs(p) {
		wd, err := os.Getwd()
		if err != nil {
			return nil
		}
		p = wd + string(filepath.Separator) + p
	}
	forms := []string{g.walkSymlinks(p)}
	// Windows junctions are not reported as symlinks by Lstat. Elsewhere this would only
	// repeat the walk, on a path checked for every word of every command.
	if runtime.GOOS == "windows" && len(p) <= maxLookupPathBytes() {
		if resolved, err := filepath.EvalSymlinks(p); err == nil {
			forms = append(forms, resolved)
		}
	}
	return forms
}

// maxLookupPathBytes is the longest path the OS could accept in one call. Longer ones are
// treated as missing without a filesystem call.
func maxLookupPathBytes() int {
	if runtime.GOOS == "windows" {
		return 32767
	}
	return 4096
}

func (g *transcriptGuard) lstat(p string) (os.FileMode, error) {
	if result, ok := g.lookups[p]; ok {
		return result.mode, result.err
	}
	g.lookupRuns++
	if g.lookupRuns > maxGuardLookups {
		g.exceed("the number of paths in a call")
		return 0, os.ErrNotExist
	}
	var mode os.FileMode
	info, err := os.Lstat(p)
	if err == nil {
		mode = info.Mode()
	}
	if len(p) <= lookupCacheBytes {
		g.lookups[p] = lookupResult{mode: mode, err: err}
	}
	return mode, err
}

// walkSymlinks resolves p the way the OS does: one component at a time, so ".." applies
// after a symlink, and a missing component (a file about to be created, or the target of a
// dangling link) is kept as written instead of failing like filepath.EvalSymlinks. It keeps
// a stack of components in one buffer, so its work is linear in the length of p.
func (g *transcriptGuard) walkSymlinks(p string) string {
	separator := string(filepath.Separator)
	volume := filepath.VolumeName(p)
	buf := append(make([]byte, 0, len(p)+1), volume...)
	var ends []int // where each resolved component ends in buf
	// pending is a stack with the next component on top, so a symlink's target is pushed in O(its length).
	pending := reversedComponents(p[len(volume):], nil)
	missing := false
	hops := 0
	for len(pending) > 0 && g.overBudget == "" {
		component := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		g.components++
		if g.components > maxGuardComponents {
			g.exceed("the length of the paths in a call")
			break
		}
		switch component {
		case ".":
			continue
		case "..":
			if len(ends) > 0 {
				ends = ends[:len(ends)-1]
				buf = buf[:len(volume)]
				if len(ends) > 0 {
					buf = buf[:ends[len(ends)-1]]
				}
			}
			missing = false
			continue
		}
		buf = append(append(buf, separator...), component...)
		ends = append(ends, len(buf))
		if missing || len(buf) > maxLookupPathBytes() {
			missing = true
			continue
		}
		current := string(buf)
		mode, err := g.lstat(current)
		missing = err != nil
		if err != nil || mode&os.ModeSymlink == 0 {
			continue
		}
		target, err := os.Readlink(current)
		g.lookupRuns++
		if err != nil {
			continue
		}
		hops++
		g.hops++
		if hops > maxSymlinkHops || g.hops > maxGuardHops {
			g.exceed("a chain of symlinks")
			break
		}
		// The link itself is not part of the resolved path; its target replaces it.
		ends = ends[:len(ends)-1]
		buf = buf[:len(volume)]
		if len(ends) > 0 {
			buf = buf[:ends[len(ends)-1]]
		}
		if filepath.IsAbs(target) {
			targetVolume := filepath.VolumeName(target)
			buf = append(buf[:0], targetVolume...)
			volume = targetVolume
			ends = ends[:0]
			target = target[len(targetVolume):]
		}
		pending = reversedComponents(target, pending)
	}
	if len(buf) == len(volume) {
		return volume + separator
	}
	return string(buf)
}

// reversedComponents pushes p's components onto a stack, so the first one is on top.
func reversedComponents(p string, stack []string) []string {
	parts := strings.FieldsFunc(p, func(r rune) bool { return r < 0x80 && os.IsPathSeparator(uint8(r)) })
	for i := len(parts) - 1; i >= 0; i-- {
		stack = append(stack, parts[i])
	}
	return stack
}

func expandHome(p string) string {
	home, err := userHomeDir()
	if err != nil {
		return p
	}
	return expandHomeWith(p, home)
}

// expandHomeWith replaces a leading home-directory spelling (see homePrefixes) with home.
func expandHomeWith(p, home string) string {
	if home == "" {
		return p
	}
	for _, prefix := range homePrefixes {
		if p == prefix {
			return home
		}
		if rest, ok := strings.CutPrefix(p, prefix); ok && (rest[0] == '/' || rest[0] == '\\') {
			return home + rest
		}
	}
	return p
}

// isAntigravitySystemPath reports whether p, joined with cwd when relative and lexically
// cleaned, points into the ".system_generated" subtree of an Antigravity conversation
// (~/.gemini/antigravity/brain/<id>/.system_generated/...). Other artifacts under
// brain/<id>/ (e.g. task.md) are not matched.
func isAntigravitySystemPath(p, cwd string) bool {
	if isFileURI(p) {
		p = extractFilePathFromURI(p)
	}
	p = normalizePathSeparators(p)
	if !path.IsAbs(p) && cwd != "" {
		p = normalizePathSeparators(cwd) + "/" + p
	}
	segs := strings.Split(strings.ToLower(path.Clean(p)), "/")
	for i := 0; i+2 < len(segs); i++ {
		if segs[i] != ".gemini" || segs[i+1] != "antigravity" || segs[i+2] != "brain" {
			continue
		}
		// One scan of the rest answers for every later match too.
		for _, seg := range segs[i+3:] {
			if seg == ".system_generated" {
				return true
			}
		}
		return false
	}
	return false
}
