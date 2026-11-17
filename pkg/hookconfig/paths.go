// Package hookconfig defines the harness files that can control jev-guard hooks.
package hookconfig

import "path/filepath"

// File is relative to a project root or the user's home directory. Install marks
// the default destination used by init; overrides are protected as well.
type File struct {
	Agent   string
	Project string
	User    string
	Install bool
}

// Files returns a fresh list so callers cannot change the security policy.
func Files() []File {
	return []File{
		{"claude", ".claude/settings.json", ".claude/settings.json", true},
		{"claude", ".claude/settings.local.json", ".claude/settings.local.json", false},
		{"codex", ".codex/hooks.json", ".codex/hooks.json", true},
		{"codex", ".codex/config.toml", ".codex/config.toml", false},
		{"antigravity", ".agents/hooks.json", ".gemini/config/hooks.json", true},
	}
}

// SettingsPath is the installer destination for the selected agent and scope.
func SettingsPath(agent, scope, cwd, home string) string {
	for _, file := range Files() {
		if file.Agent == agent && file.Install {
			if scope == "user" {
				return filepath.Join(home, filepath.FromSlash(file.User))
			}
			return filepath.Join(cwd, filepath.FromSlash(file.Project))
		}
	}
	return SettingsPath("antigravity", scope, cwd, home)
}
