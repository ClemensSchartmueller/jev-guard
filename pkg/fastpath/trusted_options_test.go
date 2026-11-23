package fastpath

import (
	"testing"

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
		{"git branch topic", false},
		{"git branch --unknown", false},
		{"git status --short", true},
		{"git diff --stat", true},
		{"git diff --unknown", false},
		{"git log --oneline -5", true},
		{"git show HEAD", true},
		{"ls -la src", true},
		{"ls --unknown", false},
		{"node -v", true},
		{"node -v extra", false},
		{"echo %EXAMPLE%", false},
		{"echo !EXAMPLE!", false},
		{"echo a^b", false},
	} {
		t.Run(tt.command, func(t *testing.T) {
			call := &harness.NormalizedToolCall{ToolName: "run_command", Command: tt.command}
			result := filter.Evaluate(call)
			if tt.allow {
				if result == nil || result.Decision != harness.DecisionAllow || result.Source != "fastpath_trusted" {
					t.Fatalf("expected trusted ALLOW, got %+v", result)
				}
			} else if result != nil {
				t.Fatalf("expected deferral, got %+v", result)
			}
		})
	}
}
