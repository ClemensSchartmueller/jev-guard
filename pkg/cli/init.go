package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var initAgents = []string{"claude", "codex", "antigravity"}

func (r *Runner) handleInit(args []string) (Action, int) {
	agent, scope := "", "project"
	for i := 0; i < len(args); i++ {
		if value, ok := initFlag(args, &i, "--agent"); ok {
			if value == "" {
				fmt.Fprintln(r.Stderr, "Error: --agent requires a value")
				return ActionHandled, 1
			}
			agent = strings.ToLower(value)
			continue
		}
		if value, ok := initFlag(args, &i, "--scope"); ok {
			scope = strings.ToLower(value)
			continue
		}
		if args[i] == "--help" || args[i] == "-h" {
			fmt.Fprintln(r.Stdout, "Usage: jev-guard init [--agent claude|codex|antigravity|all] [--scope project|user]")
			return ActionHandled, 0
		}
		fmt.Fprintf(r.Stderr, "Error: unknown init option %q\n", args[i])
		return ActionHandled, 1
	}
	if scope != "project" && scope != "user" {
		fmt.Fprintf(r.Stderr, "Error: invalid scope %q (expected project or user)\n", scope)
		return ActionHandled, 1
	}
	if agent != "" && agent != "all" && agent != "claude" && agent != "codex" && agent != "antigravity" {
		fmt.Fprintf(r.Stderr, "Error: invalid agent %q (expected claude, codex, antigravity, or all)\n", agent)
		return ActionHandled, 1
	}
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(r.Stderr, "Error: find current directory: %v\n", err)
		return ActionHandled, 1
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(r.Stderr, "Error: find home directory: %v\n", err)
		return ActionHandled, 1
	}
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(r.Stderr, "Error: find jev-guard executable: %v\n", err)
		return ActionHandled, 1
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		fmt.Fprintf(r.Stderr, "Error: resolve jev-guard executable: %v\n", err)
		return ActionHandled, 1
	}
	command, err := quoteHookExecutable(exe)
	if err != nil {
		fmt.Fprintf(r.Stderr, "Error: unsafe jev-guard executable path: %v\n", err)
		return ActionHandled, 1
	}
	selected := selectInitAgents(agent, scope, cwd, home)
	if agent == "" {
		fmt.Fprintf(r.Stdout, "Detected agents: %s\n", strings.Join(selected, ", "))
	}
	failed := false
	for _, name := range selected {
		path := initSettingsPath(name, scope, cwd, home)
		changed, err := installAgentHooks(path, name, command)
		if err != nil {
			fmt.Fprintf(r.Stderr, "Error: %s: %v\n", name, err)
			failed = true
			continue
		}
		status := "already configured"
		if changed {
			status = "configured"
		}
		fmt.Fprintf(r.Stdout, "%s: %s (%s)\n", name, status, path)
	}
	if failed {
		return ActionHandled, 1
	}
	fmt.Fprintln(r.Stdout, "Run `jev-guard config show` to check policy and API key status.")
	if agent == "codex" || agent == "all" || containsAgent(selected, "codex") {
		fmt.Fprintln(r.Stdout, "Codex: review and trust the project hooks with `/hooks` before they can run. New or changed hooks (including UserPromptSubmit and Stop) must be re-trusted.")
	}
	return ActionHandled, 0
}

func initFlag(args []string, i *int, name string) (string, bool) {
	if args[*i] == name {
		if *i+1 >= len(args) {
			return "", true
		}
		*i++
		return args[*i], true
	}
	if strings.HasPrefix(args[*i], name+"=") {
		return strings.TrimPrefix(args[*i], name+"="), true
	}
	return "", false
}

func selectInitAgents(requested, scope, cwd, home string) []string {
	if requested != "" && requested != "all" {
		return []string{requested}
	}
	if requested == "all" {
		return initAgents
	}
	root := cwd
	if scope == "user" {
		root = home
	}
	var detected []string
	for _, agent := range initAgents {
		path := initSettingsPath(agent, scope, cwd, home)
		if _, err := os.Stat(path); err == nil {
			detected = append(detected, agent)
			continue
		}
		dir := filepath.Dir(path)
		if scope == "project" {
			dir = filepath.Join(root, map[string]string{"claude": ".claude", "codex": ".codex", "antigravity": ".agents"}[agent])
		}
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			detected = append(detected, agent)
		}
	}
	if len(detected) > 0 {
		return detected
	}
	return initAgents
}

func initSettingsPath(agent, scope, cwd, home string) string {
	if scope == "user" {
		switch agent {
		case "claude":
			return filepath.Join(home, ".claude", "settings.json")
		case "codex":
			return filepath.Join(home, ".codex", "hooks.json")
		default:
			return filepath.Join(home, ".gemini", "config", "hooks.json")
		}
	}
	switch agent {
	case "claude":
		return filepath.Join(cwd, ".claude", "settings.json")
	case "codex":
		return filepath.Join(cwd, ".codex", "hooks.json")
	default:
		return filepath.Join(cwd, ".agents", "hooks.json")
	}
}

func containsAgent(agents []string, name string) bool {
	for _, agent := range agents {
		if agent == name {
			return true
		}
	}
	return false
}

func quoteHookExecutable(path string) (string, error) {
	return quoteHookExecutableForOS(path, runtime.GOOS)
}

func quoteHookExecutableForOS(path, goos string) (string, error) {
	if strings.ContainsAny(path, "\r\n\x00") {
		return "", fmt.Errorf("path contains a control character")
	}
	if goos == "windows" {
		// Hook commands are shell strings; cmd.exe and PowerShell expand these inside quotes.
		if strings.ContainsAny(path, "%!$`^") || strings.Contains(path, `"`) {
			return "", fmt.Errorf("Windows path contains a shell expansion character")
		}
		return `"` + path + `"`, nil
	}
	return "'" + strings.ReplaceAll(path, "'", `'"'"'`) + "'", nil
}

func installAgentHooks(path, agent, command string) (bool, error) {
	root := map[string]interface{}{}
	mode := os.FileMode(0600)
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() {
			return false, fmt.Errorf("refusing non-regular settings file %s", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return false, err
		}
		if err := json.Unmarshal(data, &root); err != nil || root == nil {
			return false, fmt.Errorf("invalid JSON object at %s: %v", path, err)
		}
		mode = info.Mode().Perm()
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	var section map[string]interface{}
	if agent == "antigravity" {
		section, err = childObject(root, "jev-guard")
	} else {
		section, err = childObject(root, "hooks")
	}
	if err != nil {
		return false, err
	}
	changed := false
	if agent == "antigravity" {
		if enabled, present := section["enabled"]; present {
			value, ok := enabled.(bool)
			if !ok {
				return false, fmt.Errorf("jev-guard.enabled must be a JSON boolean")
			}
			if !value {
				section["enabled"] = true
				changed = true
			}
		}
	}
	if agent == "claude" || agent == "codex" {
		c, err := ensureHook(section, "UserPromptSubmit", ".*", command+" ingest", false)
		if err != nil {
			return false, err
		}
		changed = changed || c
		c, err = ensureHook(section, "Stop", "", command+" end-turn", false)
		if err != nil {
			return false, err
		}
		changed = changed || c
	} else if agent == "antigravity" {
		// Antigravity's documented PreInvocation payload does not expose prompt text.
		// Remove the older managed ingest hook instead of installing a hook that
		// always fails validation, while preserving any unrelated user hooks.
		c, err := removeManagedDirectHook(section, "PreInvocation", command+" ingest")
		if err != nil {
			return false, err
		}
		changed = changed || c
	}
	matcher := map[string]string{
		"claude":      "Bash|Edit|Write|View|ReadLocalFile|LS|Grep|Glob",
		"codex":       "Bash|exec_command|apply_patch|view_file|read_file|list_dir",
		"antigravity": "run_command|write_to_file|replace_file_content|multi_replace_file_content|view_file|list_dir|grep_search|find_by_name|read_resource|read_url_content",
	}[agent]
	c, err := ensureHook(section, "PreToolUse", matcher, command, false)
	if err != nil {
		return false, err
	}
	changed = changed || c
	if !changed {
		return false, nil
	}
	output, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return false, err
	}
	output = append(output, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return false, err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".jev-guard-hooks-*")
	if err != nil {
		return false, err
	}
	defer os.Remove(temp.Name())
	if err := temp.Chmod(mode); err != nil {
		temp.Close()
		return false, err
	}
	if _, err := temp.Write(output); err != nil {
		temp.Close()
		return false, err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return false, err
	}
	if err := temp.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(temp.Name(), path); err != nil {
		return false, err
	}
	return true, nil
}

func childObject(root map[string]interface{}, key string) (map[string]interface{}, error) {
	if value, ok := root[key]; ok {
		child, ok := value.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("%s must be a JSON object", key)
		}
		return child, nil
	}
	child := map[string]interface{}{}
	root[key] = child
	return child, nil
}

func ensureHook(section map[string]interface{}, event, matcher, command string, direct bool) (bool, error) {
	var entries []interface{}
	if value, ok := section[event]; ok {
		var ok bool
		entries, ok = value.([]interface{})
		if !ok {
			return false, fmt.Errorf("%s must be a JSON array", event)
		}
	}
	for _, entry := range entries {
		item, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		if direct {
			if old, ok := item["command"].(string); ok && managedHookCommand(old, command) {
				if old == command {
					return false, nil
				}
				item["command"] = command
				return true, nil
			}
			continue
		}
		hooks, ok := item["hooks"].([]interface{})
		if !ok {
			continue
		}
		for index, hook := range hooks {
			obj, ok := hook.(map[string]interface{})
			if !ok {
				continue
			}
			if old, ok := obj["command"].(string); ok && managedHookCommand(old, command) {
				currentMatcher, _ := item["matcher"].(string)
				if old == command && currentMatcher == matcher {
					return false, nil
				}
				if len(hooks) == 1 {
					obj["command"] = command
					setMatcher(item, matcher)
					return true, nil
				}
				if currentMatcher == matcher {
					obj["command"] = command
					return true, nil
				}
				// Keep the shared matcher's behavior for unrelated handlers.
				item["hooks"] = append(hooks[:index:index], hooks[index+1:]...)
				section[event] = append(entries, newHookEntry(matcher, command))
				return true, nil
			}
		}
	}
	var entry interface{}
	if direct {
		entry = map[string]interface{}{"type": "command", "command": command}
	} else {
		entry = newHookEntry(matcher, command)
	}
	section[event] = append(entries, entry)
	return true, nil
}

// newHookEntry builds a command hook group; an empty matcher is omitted (events such as Stop take none).
func newHookEntry(matcher, command string) map[string]interface{} {
	entry := map[string]interface{}{"hooks": []interface{}{map[string]interface{}{"type": "command", "command": command}}}
	setMatcher(entry, matcher)
	return entry
}

func setMatcher(item map[string]interface{}, matcher string) {
	if matcher == "" {
		delete(item, "matcher")
		return
	}
	item["matcher"] = matcher
}

func removeManagedDirectHook(section map[string]interface{}, event, command string) (bool, error) {
	value, exists := section[event]
	if !exists {
		return false, nil
	}
	entries, ok := value.([]interface{})
	if !ok {
		return false, fmt.Errorf("%s must be a JSON array", event)
	}
	kept := make([]interface{}, 0, len(entries))
	removed := false
	for _, entry := range entries {
		item, ok := entry.(map[string]interface{})
		if ok {
			if existing, ok := item["command"].(string); ok && managedHookCommand(existing, command) {
				removed = true
				continue
			}
		}
		kept = append(kept, entry)
	}
	if !removed {
		return false, nil
	}
	if len(kept) == 0 {
		delete(section, event)
	} else {
		section[event] = kept
	}
	return true, nil
}

func managedHookCommand(existing, desired string) bool {
	if existing == desired {
		return true
	}
	subcommand := ""
	for _, suffix := range []string{" ingest", " end-turn"} {
		if strings.HasSuffix(desired, suffix) {
			subcommand = suffix
		}
		if strings.HasSuffix(existing, suffix) != strings.HasSuffix(desired, suffix) {
			return false
		}
	}
	base := strings.TrimSuffix(existing, subcommand)
	base = strings.Trim(base, `"'`)
	base = strings.ReplaceAll(base, `\`, "/")
	name := filepath.Base(base)
	return name == "jev-guard" || name == "jev-guard.exe"
}
