package fastpath

import (
	"testing"

	"jev-guard/pkg/harness"
)

func TestFastPath_ShellProviderAndHomeArgsNotTrusted(t *testing.T) {
	filter := NewDefaultFilter()

	cmds := []string{
		`ls env:`,
		`ls env:OPENAI_API_KEY`,
		`dir HKCU:\Software`,
		`dir cert:`,
		`ls variable:`,
		`dir function:`,
		`ls alias:`,
		`dir Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER`,
		`dir Registry::HKEY_LOCAL_MACHINE`,
		`ls -Path env:`,
		`ls -Path:env:`,
		`ls --path=env:`,
		`ls ~/Documents`,
		`dir ~\Documents`,
		`ls ~`,
	}

	for _, tool := range []string{"PowerShell", "Bash"} {
		for _, cmd := range cmds {
			call := &harness.NormalizedToolCall{
				ToolName:       tool,
				Command:        cmd,
				WorkspaceRoots: []string{"."},
			}
			res := filter.Evaluate(call)
			if res != nil && res.Decision == harness.DecisionAllow {
				t.Errorf("%s: %q must not be fast-path ALLOWed, got %+v", tool, cmd, res)
			}
		}
	}
}

func TestFastPath_PowerShellInWorkspaceListingStillTrusted(t *testing.T) {
	filter := NewDefaultFilter()

	for _, cmd := range []string{`ls pkg`, `dir fastpath`} {
		call := &harness.NormalizedToolCall{
			ToolName:       "PowerShell",
			Command:        cmd,
			WorkspaceRoots: []string{"."},
		}
		res := filter.Evaluate(call)
		if res == nil || res.Decision != harness.DecisionAllow {
			t.Errorf("expected ALLOW for in-workspace %q, got %+v", cmd, res)
		}
	}
}
