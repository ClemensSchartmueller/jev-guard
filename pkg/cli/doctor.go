package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"jev-guard/pkg/config"
)

const (
	doctorOK   = "[OK]  "
	doctorWarn = "[WARN]"
	doctorFail = "[FAIL]"
)

var doctorAgents = []string{"claude", "codex", "antigravity"}

func (r *Runner) handleDoctor(args []string) (Action, int) {
	offline := false
	for _, arg := range args {
		switch arg {
		case "--offline":
			offline = true
		case "-h", "--help":
			fmt.Fprintln(r.Stdout, "Usage: jev-guard doctor [--offline]")
			return ActionHandled, 0
		default:
			fmt.Fprintf(r.Stderr, "Error: unknown doctor flag %q\n", arg)
			return ActionHandled, 1
		}
	}
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(r.Stderr, "Error: find current directory: %v\n", err)
		return ActionHandled, 1
	}
	return ActionHandled, r.runDoctor(config.LoadConfig(cwd), cwd, offline)
}

// runDoctor prints one line per check and returns 1 if any check failed, else 0.
func (r *Runner) runDoctor(cfg *config.Config, cwd string, offline bool) int {
	failed := false
	report := func(level, format string, a ...interface{}) {
		if level == doctorFail {
			failed = true
		}
		fmt.Fprintf(r.Stdout, "%s %s\n", level, fmt.Sprintf(format, a...))
	}

	// 1. User config and mode.
	path := cfg.UserConfigPath
	switch {
	case path == "":
		report(doctorFail, "User config: path unavailable")
	default:
		if _, err := os.Stat(path); err != nil {
			report(doctorWarn, "User config: %s not found; using built-in defaults", path)
		} else if len(cfg.Diagnostics) > 0 {
			report(doctorFail, "User config: %s problem: %s", path, strings.Join(cfg.Diagnostics, "; "))
		} else {
			report(doctorOK, "User config: %s loaded", path)
		}
	}
	if cfg.Mode == "audit" {
		report(doctorWarn, "Mode: audit (decisions are logged but not enforced)")
	} else {
		report(doctorOK, "Mode: %s", cfg.Mode)
	}

	// 2. API key (never printed beyond a short masked prefix).
	if cfg.APIKey == "" {
		report(doctorWarn, "API key: not configured (set TYPESAFE_API_KEY or api_key in user config)")
	} else {
		report(doctorOK, "API key: configured (%s) from %s", maskKey(cfg.APIKey), cfg.Sources["api_key"])
	}

	// 3. Network. The API key is deliberately never sent.
	baseURL := effectiveBaseURL(cfg.BaseURL)
	if offline {
		report(doctorOK, "Network: skipped (--offline)")
	} else {
		timeout := time.Duration(effectiveTimeout(cfg.TimeoutMs)) * time.Millisecond
		if cfg.Timeout > 0 {
			timeout = cfg.Timeout
		}
		client := r.HTTPClient
		if client == nil {
			client = &http.Client{}
		}
		c := *client
		c.Timeout = timeout
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		start := time.Now()
		resp, err := c.Get(baseURL)
		if err != nil {
			report(doctorFail, "Network: %s unreachable within %s: %v", baseURL, timeout, err)
		} else {
			resp.Body.Close()
			report(doctorOK, "Network: %s reachable (HTTP %d, %d ms)", baseURL, resp.StatusCode, time.Since(start).Milliseconds())
		}
	}

	// 4. Model and feature flags.
	report(doctorOK, "Model: %s; fastpath: %t; context awareness: %t", effectiveValue(cfg.Model, "jev-latest"), cfg.IsFastpathEnabled(), cfg.IsContextAwarenessEnabled())

	// 5. Workspace.
	if root := doctorGitRoot(cwd); root != "" {
		report(doctorOK, "Workspace: cwd %s, git root %s", cwd, root)
	} else {
		report(doctorWarn, "Workspace: cwd %s, no git root found", cwd)
	}

	// 6. Audit log directory.
	if cfg.AuditLogPath == "" {
		report(doctorOK, "Audit log: not configured")
	} else if err := checkDirWritable(filepath.Dir(cfg.AuditLogPath)); err != nil {
		report(doctorFail, "Audit log: directory for %s not writable: %v", cfg.AuditLogPath, err)
	} else {
		report(doctorOK, "Audit log: directory for %s is writable", cfg.AuditLogPath)
	}

	// 7. Hooks.
	for _, agent := range doctorAgents {
		hookPath := initSettingsPath(agent, "project", cwd, "")
		command, status := findPreToolUseCommand(hookPath, agent)
		switch status {
		case "missing":
			report(doctorWarn, "Hooks (%s): %s not found; run `jev-guard init --agent %s`", agent, hookPath, agent)
		case "invalid":
			report(doctorFail, "Hooks (%s): %s is not valid JSON", agent, hookPath)
		case "none":
			report(doctorWarn, "Hooks (%s): %s has no jev-guard PreToolUse entry", agent, hookPath)
		default:
			exe := hookExecutable(command)
			if resolved, ok := resolveExecutable(exe); ok {
				report(doctorOK, "Hooks (%s): PreToolUse registered in %s; command %s", agent, hookPath, resolved)
			} else {
				report(doctorFail, "Hooks (%s): PreToolUse registered in %s but command %q not found", agent, hookPath, exe)
			}
		}
	}

	if failed {
		return 1
	}
	return 0
}

func maskKey(key string) string {
	if len(key) <= 3 {
		return "***"
	}
	return key[:3] + "***"
}

func doctorGitRoot(start string) string {
	curr := filepath.Clean(start)
	for {
		if _, err := os.Lstat(filepath.Join(curr, ".git")); err == nil {
			return curr
		}
		parent := filepath.Dir(curr)
		if parent == curr {
			return ""
		}
		curr = parent
	}
}

func checkDirWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".jev-guard-doctor-*")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}

// findPreToolUseCommand returns the jev-guard PreToolUse command and a status of
// "found", "missing" (no file), "invalid" (bad JSON) or "none" (no entry).
func findPreToolUseCommand(path, agent string) (string, string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "missing"
	}
	var root map[string]interface{}
	if json.Unmarshal(data, &root) != nil || root == nil {
		return "", "invalid"
	}
	key := "hooks"
	if agent == "antigravity" {
		key = "jev-guard"
	}
	section, _ := root[key].(map[string]interface{})
	entries, _ := section["PreToolUse"].([]interface{})
	for _, entry := range entries {
		item, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		hooks, _ := item["hooks"].([]interface{})
		for _, hook := range hooks {
			obj, ok := hook.(map[string]interface{})
			if !ok {
				continue
			}
			if cmd, ok := obj["command"].(string); ok && managedHookCommand(cmd, cmd) && !strings.HasSuffix(cmd, " ingest") {
				return cmd, "found"
			}
		}
	}
	return "", "none"
}

// hookExecutable extracts the executable from a hook command, honoring quotes.
func hookExecutable(command string) string {
	command = strings.TrimSpace(command)
	if command != "" && (command[0] == '"' || command[0] == '\'') {
		if end := strings.IndexByte(command[1:], command[0]); end >= 0 {
			return command[1 : end+1]
		}
		return command[1:]
	}
	if fields := strings.Fields(command); len(fields) > 0 {
		return fields[0]
	}
	return ""
}

func resolveExecutable(exe string) (string, bool) {
	if exe == "" {
		return "", false
	}
	if filepath.IsAbs(exe) {
		if info, err := os.Stat(exe); err == nil && !info.IsDir() {
			return exe, true
		}
		return "", false
	}
	p, err := exec.LookPath(exe)
	return p, err == nil
}
