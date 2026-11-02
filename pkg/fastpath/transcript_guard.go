package fastpath

import (
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"jev-guard/pkg/harness"
)

// maxSymlinkHops bounds symlink following. A chain this long fails in the OS too.
const maxSymlinkHops = 64

// homePrefixes are spellings of the home directory that a tool or shell expands itself.
var homePrefixes = []string{"~", "$HOME", "${HOME}", "$env:HOME", "$env:USERPROFILE", "%USERPROFILE%", "%HOME%"}

// CheckTranscriptTampering denies access to the Antigravity conversation transcript. The
// gate calls it directly when the fast path is disabled, because the transcript is still
// read as user intent. Returns nil when the call is clean.
func CheckTranscriptTampering(call *harness.NormalizedToolCall) *harness.EvaluationResult {
	if call == nil {
		return nil
	}
	reason := transcriptTamperingReason(call)
	if reason == "" {
		return nil
	}
	return &harness.EvaluationResult{
		Decision:   harness.DecisionDeny,
		Reason:     reason,
		Source:     "fastpath_tampering",
		Confidence: 1.0,
	}
}

// transcriptTamperingReason protects the transcript that Antigravity prompt intent is
// read from: an agent that could write it could forge the user's authorization. Every path
// input is checked as written and as the filesystem would resolve it, so a symlink cannot
// hide the transcript. A path computed when a shell command runs is out of reach here.
func transcriptTamperingReason(call *harness.NormalizedToolCall) string {
	dirs := callWorkingDirs(call)
	targets := append([]string{call.TargetPath}, dirs...)
	for _, key := range harness.PathArgKeys {
		targets = append(targets, stringValues(call.RawArgs[key])...)
	}
	for _, target := range targets {
		for _, form := range pathForms(target, dirs) {
			if isAntigravitySystemPath(form, "") {
				return "Direct access to Antigravity conversation transcript/system state is prohibited"
			}
		}
	}

	// Commands are matched more broadly on purpose: shell globs and variables
	// (e.g. ~/.gemini/antigravity/brain/*/.sys*/logs/t*) cannot be parsed reliably.
	lowerCommand := strings.ToLower(normalizePathSeparators(call.Command))
	if strings.Contains(lowerCommand, "antigravity/brain") || strings.Contains(lowerCommand, ".system_generated") || strings.Contains(lowerCommand, "transcript.jsonl") {
		return "Access to Antigravity conversation transcript/system state via command is prohibited"
	}
	// A word that resolves anywhere under the brain directory gets the same answer as
	// spelling that path out, so a link to a conversation directory cannot be moved or replaced.
	for _, token := range commandPathTokens(call.Command) {
		for _, form := range pathForms(token, dirs) {
			if strings.Contains(strings.ToLower(normalizePathSeparators(form)), "/.gemini/antigravity/brain") {
				return "Access to Antigravity conversation transcript/system state via command is prohibited"
			}
		}
	}

	return ""
}

// callWorkingDirs returns the directories relative paths may be resolved against: the
// normalized one and any other working-directory argument, which the tool may honor instead.
func callWorkingDirs(call *harness.NormalizedToolCall) []string {
	var dirs []string
	if cwd := strings.TrimSpace(call.Cwd); cwd != "" {
		dirs = append(dirs, cwd)
	}
	for _, key := range harness.CwdArgKeys {
		for _, value := range stringValues(call.RawArgs[key]) {
			if value = strings.TrimSpace(value); value == "" {
				continue
			}
			if base := strings.TrimSpace(call.Cwd); base != "" && !filepath.IsAbs(value) {
				value = base + string(filepath.Separator) + value
			}
			dirs = append(dirs, value)
		}
	}
	return dirs
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

// pathForms returns p as written and resolved against each working directory, without
// requiring it to exist. Absolute forms are cleaned lexically by the caller's matcher.
func pathForms(p string, dirs []string) []string {
	p = strings.TrimSpace(p)
	if p == "" || isURL(p) {
		return nil
	}
	if isFileURI(p) {
		p = extractFilePathFromURI(p)
		if decoded, err := url.PathUnescape(p); err == nil {
			p = decoded
		}
	}
	forms := []string{p}
	p = expandHome(p)
	if filepath.IsAbs(p) {
		return append(forms, resolvedForms(p)...)
	}
	if len(dirs) == 0 {
		if wd, err := os.Getwd(); err == nil {
			dirs = []string{wd}
		}
	}
	for _, dir := range dirs {
		// Deliberately not filepath.Join, which would remove ".." before symlinks are seen.
		joined := dir + string(filepath.Separator) + p
		forms = append(forms, normalizePathSeparators(joined))
		forms = append(forms, resolvedForms(joined)...)
	}
	return forms
}

func resolvedForms(abs string) []string {
	forms := []string{walkSymlinks(abs)}
	// EvalSymlinks also handles what Lstat does not report as a symlink, such as Windows junctions.
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		forms = append(forms, resolved)
	}
	return forms
}

// walkSymlinks resolves p the way the OS does: one component at a time, so ".." applies
// after a symlink, and a missing component (a file about to be created, or the target of a
// dangling link) is kept as written instead of failing like filepath.EvalSymlinks.
func walkSymlinks(p string) string {
	volume := filepath.VolumeName(p)
	current := volume + string(filepath.Separator)
	pending := splitPath(p[len(volume):])
	for hops := 0; len(pending) > 0; {
		component := pending[0]
		pending = pending[1:]
		switch component {
		case ".":
			continue
		case "..":
			current = filepath.Dir(current)
			continue
		}
		next := filepath.Join(current, component)
		info, err := os.Lstat(next)
		if err != nil || info.Mode()&os.ModeSymlink == 0 || hops >= maxSymlinkHops {
			current = next
			continue
		}
		target, err := os.Readlink(next)
		if err != nil {
			current = next
			continue
		}
		hops++
		if filepath.IsAbs(target) {
			targetVolume := filepath.VolumeName(target)
			current = targetVolume + string(filepath.Separator)
			target = target[len(targetVolume):]
		}
		pending = append(splitPath(target), pending...)
	}
	return current
}

func splitPath(p string) []string {
	return strings.FieldsFunc(p, func(r rune) bool { return r < 0x80 && os.IsPathSeparator(uint8(r)) })
}

func expandHome(p string) string {
	home, err := userHomeDir()
	if err != nil || home == "" {
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

// commandPathTokens lists the words of a shell command that may name a path, keeping
// quoted spans together and also splitting on operators and flag values. It is not a shell
// evaluator: it cannot see variables, globs, substitutions, or links made while the command runs.
func commandPathTokens(command string) []string {
	var tokens []string
	for _, arg := range sensitiveCommandArguments(command) {
		tokens = append(tokens, arg)
		pieces := strings.FieldsFunc(arg, func(r rune) bool { return strings.ContainsRune(";|&<>()`=", r) })
		if len(pieces) > 1 || (len(pieces) == 1 && pieces[0] != arg) {
			tokens = append(tokens, pieces...)
		}
	}
	return tokens
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
		for j := i + 3; j < len(segs); j++ {
			if segs[j] == ".system_generated" {
				return true
			}
		}
	}
	return false
}
