package fastpath

import (
	"testing"

	"jev-guard/pkg/harness"
)

func TestFastPath_Catastrophic(t *testing.T) {
	filter := NewDefaultFilter()

	cases := []string{
		"rm -rf /",
		"rm -fr /*",
		":(){ :|:& };:",
		"format c:",
	}

	for _, cmd := range cases {
		call := &harness.NormalizedToolCall{
			ToolName: "Bash",
			Command:  cmd,
		}
		res := filter.Evaluate(call)
		if res == nil {
			t.Fatalf("expected catastrophic block for %q, got nil", cmd)
		}
		if res.Decision != harness.DecisionDeny {
			t.Errorf("expected DENY for %q, got %v", cmd, res.Decision)
		}
	}
}

func TestFastPath_SensitiveFiles(t *testing.T) {
	filter := NewDefaultFilter()

	call1 := &harness.NormalizedToolCall{
		ToolName: "Bash",
		Command:  "cat .env",
	}
	res1 := filter.Evaluate(call1)
	if res1 == nil || res1.Decision != harness.DecisionAsk {
		t.Errorf("expected ASK for .env, got %+v", res1)
	}

	call2 := &harness.NormalizedToolCall{
		ToolName:   "write_to_file",
		TargetPath: "/home/user/.ssh/id_rsa",
	}
	res2 := filter.Evaluate(call2)
	if res2 == nil || res2.Decision != harness.DecisionAsk {
		t.Errorf("expected ASK for id_rsa, got %+v", res2)
	}
}

func TestFastPath_SafeWhitelist(t *testing.T) {
	filter := NewDefaultFilter()

	call1 := &harness.NormalizedToolCall{
		ToolName: "run_command",
		Command:  "git status",
	}
	res1 := filter.Evaluate(call1)
	if res1 == nil || res1.Decision != harness.DecisionAllow {
		t.Errorf("expected ALLOW for 'git status', got %+v", res1)
	}

	call2 := &harness.NormalizedToolCall{
		ToolName:   "view_file",
		TargetPath: "main.go",
	}
	res2 := filter.Evaluate(call2)
	if res2 == nil || res2.Decision != harness.DecisionAllow {
		t.Errorf("expected ALLOW for view_file, got %+v", res2)
	}

	// Should NOT allow if chained with mutator
	call3 := &harness.NormalizedToolCall{
		ToolName: "run_command",
		Command:  "git status; rm -rf /",
	}
	res3 := filter.Evaluate(call3)
	// Because rm -rf / is present, it will hit catastrophic check and DENY
	if res3 == nil || res3.Decision != harness.DecisionDeny {
		t.Errorf("expected DENY for chained catastrophic, got %+v", res3)
	}
}

func TestFastPath_MutatingPassThrough(t *testing.T) {
	filter := NewDefaultFilter()

	call := &harness.NormalizedToolCall{
		ToolName: "run_command",
		Command:  "npm install express",
	}
	res := filter.Evaluate(call)
	if res != nil {
		t.Errorf("expected nil (pass-through to semantic evaluator), got %+v", res)
	}
}

func TestFastPath_ReadTools_InsideWorkspace(t *testing.T) {
	filter := NewDefaultFilter()

	cases := []struct {
		tool   string
		target string
	}{
		{"view_file", "main.go"},
		{"View", "pkg/fastpath/filter.go"},
		{"read_file", "README.md"},
		{"list_dir", "pkg"},
		{"LS", "pkg/harness"},
		{"grep_search", "pkg"},
		{"find_by_name", "pkg"},
		{"glob", "pkg"},
	}

	for _, tc := range cases {
		call := &harness.NormalizedToolCall{
			ToolName:       tc.tool,
			TargetPath:     tc.target,
			WorkspaceRoots: []string{"."},
		}
		res := filter.Evaluate(call)
		if res == nil || res.Decision != harness.DecisionAllow {
			t.Errorf("expected ALLOW for safe read %s on %s, got %+v", tc.tool, tc.target, res)
		}
	}
}

func TestFastPath_ReadTools_OutsideWorkspace(t *testing.T) {
	filter := NewDefaultFilter()

	cases := []struct {
		tool   string
		target string
	}{
		{"view_file", "C:\\Windows\\System32\\drivers\\etc\\hosts"},
		{"View", "/etc/shadow"},
		{"read_file", "../outside.txt"},
		{"list_dir", "C:\\Users"},
		{"LS", "/var/log"},
	}

	for _, tc := range cases {
		call := &harness.NormalizedToolCall{
			ToolName:       tc.tool,
			TargetPath:     tc.target,
			WorkspaceRoots: []string{"C:\\dev\\myproject"},
			Cwd:            "C:\\dev\\myproject",
		}
		res := filter.Evaluate(call)
		if res == nil {
			t.Fatalf("expected boundary evaluation for %s on %s, got nil", tc.tool, tc.target)
		}
		if res.Decision != harness.DecisionAsk {
			t.Errorf("expected ASK for boundary escape %s on %s, got %v", tc.tool, tc.target, res.Decision)
		}
		if res.Source != "fastpath_boundary" {
			t.Errorf("expected source fastpath_boundary, got %s", res.Source)
		}
	}
}

type mockBoundaryChecker struct {
	contained bool
}

func (m *mockBoundaryChecker) IsPathContained(targetPath string, cwd string) (bool, error) {
	return m.contained, nil
}

func TestFastPath_InjectedBoundaryChecker(t *testing.T) {
	checker := &mockBoundaryChecker{contained: false}
	filter := NewFilter(checker)

	call := &harness.NormalizedToolCall{
		ToolName:   "view_file",
		TargetPath: "some/file.txt",
	}

	res := filter.Evaluate(call)
	if res == nil || res.Decision != harness.DecisionAsk {
		t.Fatalf("expected ASK for uncontained mock path, got %+v", res)
	}

	checker.contained = true
	resAllow := filter.Evaluate(call)
	if resAllow == nil || resAllow.Decision != harness.DecisionAllow {
		t.Fatalf("expected ALLOW for contained mock path, got %+v", resAllow)
	}
}

