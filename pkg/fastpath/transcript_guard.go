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

// maxSymlinkHops bounds symlink following. A chain this long fails in the OS too.
const maxSymlinkHops = 64

// maxPathLikeBytes is longer than any usable path, so a longer argument is treated as content.
const maxPathLikeBytes = 4096

// commandArgKeys hold commands, as a string or as an argument list.
var commandArgKeys = []string{"CommandLine", "command", "cmd", "script"}

// patchFileHeader finds the files an apply_patch body names.
var patchFileHeader = regexp.MustCompile(`(?m)^\*\*\* (?:Add File|Update File|Delete File|Move to): (.*)$`)

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
// hide the transcript. Inputs are resolved from their exact bytes; any trimmed or decoded
// form is checked in addition, never instead. A path computed when a shell command runs is
// out of reach here (see the limits in docs/security-model.md).
func transcriptTamperingReason(call *harness.NormalizedToolCall) string {
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
		for _, form := range pathForms(target, dirs) {
			if isAntigravitySystemPath(form, "") {
				return directReason
			}
		}
	}

	// Any other argument may be a path under a name we do not know, or just text that
	// mentions one. It only counts when it is one line and leads somewhere real.
	for _, value := range args {
		if len(value) > maxPathLikeBytes || strings.ContainsAny(value, "\r\n") {
			continue
		}
		for _, form := range pathForms(value, dirs) {
			if isAntigravitySystemPath(form, "") && parentExists(form) {
				return directReason
			}
		}
	}

	commands := []string{call.Command}
	for _, key := range commandArgKeys {
		commands = append(commands, stringValues(call.RawArgs[key])...)
	}
	for _, command := range commands {
		// Matched broadly on purpose: shell globs and variables
		// (e.g. ~/.gemini/antigravity/brain/*/.sys*/logs/t*) cannot be parsed reliably.
		if namesTranscriptInText(command) {
			return commandReason
		}
		for _, word := range shellWords(command) {
			if namesTranscriptInText(word) {
				return commandReason
			}
			// A word that resolves anywhere under the brain directory gets the same answer as
			// spelling that path out, so a link to a conversation directory cannot be moved or replaced.
			for _, form := range pathForms(word, dirs) {
				if strings.Contains(strings.ToLower(normalizePathSeparators(form)), "/.gemini/antigravity/brain") {
					return commandReason
				}
			}
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
func callWorkingDirs(call *harness.NormalizedToolCall) []string {
	var dirs []string
	add := func(dir string) {
		for _, d := range dirs {
			if d == dir {
				return
			}
		}
		if strings.TrimSpace(dir) != "" {
			dirs = append(dirs, dir)
		}
	}
	add(call.Cwd)
	add(strings.TrimSpace(call.Cwd))
	bases := append([]string(nil), dirs...)
	for _, key := range harness.CwdArgKeys {
		for _, value := range stringValues(call.RawArgs[key]) {
			for _, form := range []string{value, strings.TrimSpace(value)} {
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
	return variants
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
// directory, without requiring it to exist.
func pathForms(p string, dirs []string) []string {
	if strings.TrimSpace(p) == "" {
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
				forms = append(forms, resolvedForms(candidate)...)
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

func resolvedForms(p string) []string {
	if !filepath.IsAbs(p) {
		wd, err := os.Getwd()
		if err != nil {
			return nil
		}
		p = wd + string(filepath.Separator) + p
	}
	forms := []string{walkSymlinks(p)}
	// Windows junctions are not reported as symlinks by Lstat. Elsewhere this would only
	// repeat the walk, on a path checked for every word of every command.
	if runtime.GOOS == "windows" {
		if resolved, err := filepath.EvalSymlinks(p); err == nil {
			forms = append(forms, resolved)
		}
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
	missing := false
	for hops := 0; len(pending) > 0; {
		component := pending[0]
		pending = pending[1:]
		switch component {
		case ".":
			continue
		case "..":
			current = filepath.Dir(current)
			missing = false
			continue
		}
		next := filepath.Join(current, component)
		if missing {
			current = next
			continue
		}
		info, err := os.Lstat(next)
		missing = err != nil
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
