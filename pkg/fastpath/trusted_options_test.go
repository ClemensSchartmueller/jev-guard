package fastpath

import (
	"testing"

	"jev-guard/pkg/config"
	"jev-guard/pkg/harness"
)

func TestBuiltInTrustedCommandOptions(t *testing.T) {
	filter := NewFilter(&mockBoundaryChecker{contained: true}, nil)
	for _, tt := range []struct {
		command string
		allow   bool
	}{
		{"git branch", true},
		{"git branch --list", true},
		{"git branch --", false},
		{"git branch topic", false},
		{"git branch --unknown", false},
		{"git status --short", true},
		{"GIT STATUS --short", true},
		{"git diff --stat", true},
		{"git diff --unknown", false},
		{`git diff "--unknown"`, false},
		{"git diff -- --example", true},
		{"git log --oneline -5", true},
		{"git log -5a", false},
		{"git log -", false},
		{"git show HEAD", true},
		{"ls -la src", true},
		{"ls --unknown", false},
		{"ls --color=auto", true},
		{"ls --color=example", false},
		{"dir src", true},
		{"pwd", true},
		{"whoami", true},
		{"which git", true},
		{"where.exe git", true},
		{"node -v", true},
		{"node -v extra", false},
		{"go version", true},
		{"go version extra", false},
		{"python --version", true},
		{"python --version extra", false},
		{"echo %EXAMPLE%", false},
		{"echo !EXAMPLE!", false},
		{"echo a^b", false},
	} {
		call := &harness.NormalizedToolCall{ToolName: "run_command", Command: tt.command}
		if tt.allow {
			assertTrustedAllow(t, filter, tt.command, call)
		} else {
			assertDeferred(t, filter, tt.command, call)
		}
	}
}

func TestBuiltInTrustedCommandPoliciesMatchDefaults(t *testing.T) {
	defaults := config.DefaultTrustedCommands()
	if len(trustedInspectionCommands) != len(defaults) {
		t.Errorf("got %d built-in policies for %d default prefixes", len(trustedInspectionCommands), len(defaults))
	}
	for _, prefix := range defaults {
		if _, ok := trustedInspectionCommands[prefix]; !ok {
			t.Errorf("missing inspection policy for %q", prefix)
		}
	}
}
