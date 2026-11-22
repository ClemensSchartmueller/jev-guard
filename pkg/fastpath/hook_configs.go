package fastpath

import (
	"errors"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"jev-guard/pkg/boundary"
	"jev-guard/pkg/harness"
	"jev-guard/pkg/hookconfig"
)

// SourceHookConfig identifies changes requiring human approval even when the
// optional fast path is disabled or the user intent appears to authorize them.
const SourceHookConfig = "fastpath_hook_config"

func checkHookConfigChanges(call *harness.NormalizedToolCall) *harness.EvaluationResult {
	switch strings.ToLower(call.ToolName) {
	case "webfetch", "websearch", "web_fetch", "web_search", "readurlcontent", "search_web":
		return nil
	}
	if isSafeReadTool(call) {
		return nil
	}
	dirs := callWorkingDirs(call)
	if len(dirs) == 0 {
		if cwd, err := os.Getwd(); err == nil {
			dirs = []string{cwd}
		}
	}
	if len(dirs) == 0 {
		dirs = []string{""}
	}
	targets := append([]string{call.TargetPath}, hookConfigPathArgs(call.RawArgs)...)
	for _, text := range append(allStrings(call.RawArgs), call.Command) {
		if len(text) <= maxGuardCommandBytes {
			for _, match := range patchFileHeader.FindAllStringSubmatch(text, -1) {
				targets = append(targets, match[1])
			}
		}
	}
	reader := newShellReader()
	var commands []string
	commands = append(commands, call.Command)
	for _, key := range commandArgKeys {
		if command, ok := call.RawArgs[key].(string); ok {
			commands = append(commands, command)
		} else {
			words := stringValues(call.RawArgs[key])
			commands = append(commands, strings.Join(words, " "))
			commands = append(commands, reader.commandPayloads(words)...)
		}
	}
	for _, command := range commands {
		targets = append(targets, hookCommandTargetsMode(command, dirs, reader, 0, false, strings.EqualFold(call.ToolName, "PowerShell"), call.ToolName == "Bash")...)
	}
	if reader.incomplete() != "" {
		return hookConfigLimit()
	}
	roots := hookConfigRoots(dirs)
	if len(roots) > 128 {
		return hookConfigLimit()
	}
	names, err := hookPatternNames(roots)
	if err != nil {
		return hookConfigLimit()
	}
	seenPatterns := map[string]bool{}
	for _, target := range targets {
		if strings.Contains(target, "\x00u") {
			raw, directories, windows := hookTargetMode(target)
			match, err := hookUnknownTarget(raw, directories, windows)
			if err != nil {
				return hookConfigLimit()
			}
			if match {
				return hookConfigAsk()
			}
			continue
		}
		key := target
		target, directoryOps, windows := hookTargetMode(target)
		if !strings.ContainsAny(target, "*?[{") || seenPatterns[key] {
			continue
		}
		seenPatterns[key] = true
		match, err := hookConfigPatternMode(target, names, directoryOps, windows)
		if err != nil {
			return hookConfigLimit()
		}
		if match {
			return hookConfigAsk()
		}
	}
	var protectedPaths []string
	protectedRead := false
	for _, target := range targets {
		target, directoryOps, _ := hookTargetMode(target)
		if strings.ContainsAny(target, "*?[{") {
			continue
		}
		if isURL(target) {
			continue
		}
		for _, variant := range pathVariants(target) {
			if len(variant) > maxPathLikeBytes {
				continue
			}
			for _, dir := range dirs {
				candidate := expandVariables(variant, dir)
				if candidate == "" {
					continue
				}
				candidate = joinCwd(candidate, dir)
				// Check both spellings: replacing a symlink changes the named config,
				// while writing through an alias changes its resolved destination.
				if hookConfigName(candidate, directoryOps) {
					return hookConfigAsk()
				}
				resolved, err := boundary.CanonicalizePath(candidate)
				if err != nil {
					if errors.Is(err, boundary.ErrOSNameTooLong) {
						continue
					}
					if errors.Is(err, boundary.ErrResolutionLimit) {
						return boundaryLimitResult("Hook configuration target could not be verified: ", err)
					}
					continue // not a usable path (often a shell flag or literal argument)
				}
				if hookConfigName(resolved, directoryOps) {
					return hookConfigAsk()
				}
				// Resolve the known destinations once to catch configs that are
				// themselves symlinks, as well as aliases pointing at configs.
				if !protectedRead {
					protectedRead = true
					for _, root := range roots {
						for _, file := range hookconfig.Files() {
							relative := file.Project
							if root.user {
								relative = file.User
							}
							if root.env != "" {
								if file.Agent != root.env {
									continue
								}
								relative = filepath.Base(file.User)
							}
							protected, err := boundary.CanonicalizePath(filepath.Join(root.path, filepath.FromSlash(relative)))
							if err == nil {
								protectedPaths = append(protectedPaths, protected)
							}
							if errors.Is(err, boundary.ErrResolutionLimit) {
								return boundaryLimitResult("Hook configuration could not be verified: ", err)
							}
						}
					}
				}
				for _, protected := range protectedPaths {
					if sameHookConfigPath(protected, resolved) {
						return hookConfigAsk()
					}
				}
			}
		}
	}
	return nil
}

func hookConfigAsk() *harness.EvaluationResult {
	return &harness.EvaluationResult{Decision: harness.DecisionAsk, Reason: "Changes to harness hook configuration require human approval", Source: SourceHookConfig, Confidence: 1.0}
}

func hookConfigName(name string, directories bool) bool {
	// Case-folding on Linux is intentional: conservatively protect alternate spellings.
	name = "/" + strings.ToLower(normalizePathSeparators(filepath.Clean(name)))
	for _, file := range hookconfig.Files() {
		for _, relative := range []string{file.Project, file.User} {
			// Renaming or deleting the containing harness directory also removes
			// its hook configuration. Do not match unrelated descendants.
			for relative != "." {
				if strings.HasSuffix(name, "/"+relative) {
					return true
				}
				if !directories {
					break
				}
				relative = filepath.ToSlash(filepath.Dir(relative))
			}
		}
	}
	for _, root := range hookConfigRoots(nil) {
		if root.env == "" {
			continue
		}
		for _, file := range hookconfig.Files() {
			if file.Agent == root.env && strings.TrimLeft(name, "/") == strings.TrimLeft(strings.ToLower(normalizePathSeparators(filepath.Join(root.path, filepath.Base(file.User)))), "/") {
				return true
			}
		}
		if directories && strings.HasSuffix(name, "/"+strings.ToLower(normalizePathSeparators(root.path))) {
			return true
		}
	}
	return false
}

type hookConfigRoot struct {
	path string
	user bool
	env  string
}

func hookConfigRoots(dirs []string) []hookConfigRoot {
	var roots []hookConfigRoot
	for variable, agent := range map[string]string{"CODEX_HOME": "codex", "CLAUDE_CONFIG_DIR": "claude"} {
		if dir := os.Getenv(variable); dir != "" {
			roots = append(roots, hookConfigRoot{path: dir, env: agent})
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		roots = append(roots, hookConfigRoot{path: home, user: true})
	}
	for _, dir := range dirs {
		for dir != "" && dir != "." {
			roots = append(roots, hookConfigRoot{path: dir})
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return roots
}

func hookConfigLimit() *harness.EvaluationResult {
	return &harness.EvaluationResult{Decision: harness.DecisionAsk, Source: SourceAntiTamperingLimit, Reason: "Hook configuration analysis work budget exhausted", Confidence: 1}
}

// Build and deduplicate parents once, rather than walking every ancestor for every pattern.
func hookPatternNames(roots []hookConfigRoot) ([]string, error) {
	seen := map[string]bool{}
	add := func(name string) error {
		for name != "." && name != "/" && !seen[name] {
			if err := boundary.ChargeWork(len(name) + 1); err != nil {
				return err
			}
			seen[name] = true
			name = path.Dir(name)
		}
		return nil
	}
	for _, root := range roots {
		for _, file := range hookconfig.Files() {
			relative := file.Project
			if root.user {
				relative = file.User
			}
			if root.env != "" {
				if root.env != file.Agent {
					continue
				}
				relative = filepath.Base(file.User)
			}
			for _, name := range []string{relative, normalizePathSeparators(filepath.Join(root.path, relative))} {
				if err := add(strings.ToLower(name)); err != nil {
					return nil, err
				}
			}
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	return names, nil
}

// Target metadata keeps shell dialect and directory mutation separate from path text.
func hookTargetMode(target string) (string, bool, bool) {
	directories, windows := false, false
	for strings.HasPrefix(target, "\x00") && len(target) > 1 {
		switch target[1] {
		case 'd':
			directories = true
		case 'w':
			windows = true
		}
		target = target[2:]
	}
	return normalizePathSeparators(target), directories, windows
}

func hookConfigPattern(pattern string, names []string) (bool, error) {
	return hookConfigPatternMode(pattern, names, true, false)
}

func hookGlob(pattern, name string, windows bool) bool {
	p, n := strings.Split(pattern, "/"), strings.Split(name, "/")
	if len(p) != len(n) {
		return false
	}
	for i := range p {
		if !windows && strings.HasPrefix(n[i], ".") && !strings.HasPrefix(p[i], ".") {
			return false
		}
		// A segment the check cannot read exactly counts as a match (see globMatch).
		if match, _ := globMatch(p[i], n[i]); !match {
			return false
		}
	}
	return true
}

func hookConfigPatternMode(pattern string, names []string, directories, windows bool) (bool, error) {
	alternatives, ok := expandBraces(strings.ToLower(expandBraceSequences(expandPatternVariables(pattern))), maxPatternExpansions)
	if !ok {
		return false, boundary.ErrWorkBudgetExhausted
	}
	var basenames []string
	for _, file := range hookconfig.Files() {
		for _, relative := range []string{file.Project, file.User} {
			basenames = append(basenames, path.Base(relative))
			if directories {
				for parent := path.Dir(relative); parent != "."; parent = path.Dir(parent) {
					basenames = append(basenames, path.Base(parent))
				}
			}
		}
	}

	for _, root := range hookConfigRoots(nil) {
		if root.env != "" && directories {
			basenames = append(basenames, path.Base(root.path))
		}
	}
	for _, alternative := range alternatives {
		alternative = path.Clean(hookExpandPath(alternative, ""))
		last := path.Base(alternative)
		possible := false
		for _, name := range basenames {
			if hookGlob(last, name, windows) {
				possible = true
				break
			}
		}
		if !possible {
			continue
		}
		for _, name := range names {
			if strings.Count(alternative, "/") != strings.Count(name, "/") || !hookConfigName(name, directories) {
				continue
			}
			if err := boundary.ChargeWork((len(alternative) + 1) * (len(name) + 1)); err != nil {
				return false, err
			}
			if hookGlob(alternative, name, windows) {
				return true, nil
			}
		}
	}
	return false, nil
}

// MultiEdit and similar tools may carry a list of edits with nested path keys.
func hookConfigPathArgs(raw interface{}) []string {
	var paths []string
	switch value := raw.(type) {
	case map[string]interface{}:
		for _, key := range harness.PathArgKeys {
			paths = append(paths, stringValues(value[key])...)
		}
		for _, nested := range value {
			paths = append(paths, hookConfigPathArgs(nested)...)
		}
	case []interface{}:
		for _, nested := range value {
			paths = append(paths, hookConfigPathArgs(nested)...)
		}
	}
	return paths
}

func sameHookConfigPath(a, b string) bool {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// With an unknown cwd only relative targets use basename fallback. Absolute
// targets continue through the exact path policy above.
func hookUnknownTarget(target string, directories, windows bool) (bool, error) {
	patterns, ok := expandBraces(strings.ToLower(expandBraceSequences(expandPatternVariables(target))), maxPatternExpansions)
	if !ok {
		return false, boundary.ErrWorkBudgetExhausted
	}
	for _, pattern := range patterns {
		last := path.Base(path.Clean(pattern))
		for _, file := range hookconfig.Files() {
			for _, relative := range []string{file.Project, file.User} {
				for relative != "." {
					if err := boundary.ChargeWork((len(last) + 1) * (len(relative) + 1)); err != nil {
						return false, err
					}
					if hookGlob(last, path.Base(relative), windows) {
						return true, nil
					}
					if !directories {
						break
					}
					relative = path.Dir(relative)
				}
			}
		}
	}
	return false, nil
}
