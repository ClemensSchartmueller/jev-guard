package fastpath

import (
	"testing"

	"jev-guard/pkg/config"
	"jev-guard/pkg/harness"
)

func TestFastPath_CatastrophicDelegatesToSemantic(t *testing.T) {
	filter := NewDefaultFilter()

	cases := []string{
		"rm -rf /",
		"rm -fr /*",
		":(){ :|:& };:",
		"format c:",
		"dd if=/dev/zero of=/dev/sda",
	}

	for _, cmd := range cases {
		call := &harness.NormalizedToolCall{
			ToolName: "Bash",
			Command:  cmd,
		}
		res := filter.Evaluate(call)
		// Catastrophic commands must pass through (return nil) to Jev semantic evaluation
		if res != nil {
			t.Errorf("expected nil (delegation to Jev) for %q, got %+v", cmd, res)
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

func TestFastPath_TrustedCommands(t *testing.T) {
	filter := NewDefaultFilter()

	call1 := &harness.NormalizedToolCall{
		ToolName: "run_command",
		Command:  "git status",
	}
	res1 := filter.Evaluate(call1)
	if res1 == nil || res1.Decision != harness.DecisionAllow {
		t.Errorf("expected ALLOW for 'git status', got %+v", res1)
	}
	if res1 != nil && res1.Source != "fastpath_trusted" {
		t.Errorf("expected source fastpath_trusted, got %s", res1.Source)
	}

	call2 := &harness.NormalizedToolCall{
		ToolName:   "view_file",
		TargetPath: "main.go",
	}
	res2 := filter.Evaluate(call2)
	if res2 == nil || res2.Decision != harness.DecisionAllow {
		t.Errorf("expected ALLOW for view_file, got %+v", res2)
	}

	// Should NOT allow if chained with other commands
	call3 := &harness.NormalizedToolCall{
		ToolName: "run_command",
		Command:  "git status; rm -rf /",
	}
	res3 := filter.Evaluate(call3)
	if res3 != nil {
		t.Errorf("expected nil (delegation to Jev) for chained command, got %+v", res3)
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

func TestFastPath_ConfigInjection(t *testing.T) {
	cfg := &config.Config{
		SensitiveFiles:  []string{".secret-token"},
		TrustedCommands: []string{"cargo check"},
	}
	filter := NewFilter(nil, cfg)

	// Test custom sensitive file
	call1 := &harness.NormalizedToolCall{
		ToolName:   "write_to_file",
		TargetPath: ".secret-token",
	}
	res1 := filter.Evaluate(call1)
	if res1 == nil || res1.Decision != harness.DecisionAsk {
		t.Errorf("expected ASK for custom sensitive file, got %+v", res1)
	}

	// Test custom trusted command
	call2 := &harness.NormalizedToolCall{
		ToolName: "run_command",
		Command:  "cargo check --all",
	}
	res2 := filter.Evaluate(call2)
	if res2 == nil || res2.Decision != harness.DecisionAllow {
		t.Errorf("expected ALLOW for custom trusted command, got %+v", res2)
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
	filter := NewFilter(checker, nil)

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

func TestFastPath_AntiTampering(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("JEV_GUARD_HOME", tempHome)

	filter := NewDefaultFilter()

	callTarget := &harness.NormalizedToolCall{
		ToolName:   "write_to_file",
		TargetPath: tempHome + "/sessions/override.json",
	}
	resTarget := filter.Evaluate(callTarget)
	if resTarget == nil || resTarget.Decision != harness.DecisionDeny {
		t.Fatalf("expected DENY for writing to jevguard home, got %+v", resTarget)
	}

	callCmd := &harness.NormalizedToolCall{
		ToolName: "run_command",
		Command:  "cat ~/.jevguard/sessions/default.json",
	}
	resCmd := filter.Evaluate(callCmd)
	if resCmd == nil || resCmd.Decision != harness.DecisionDeny {
		t.Fatalf("expected DENY for command accessing .jevguard, got %+v", resCmd)
	}
}

func TestFastPath_SensitiveFiles_WithIntentDefers(t *testing.T) {
	filter := NewDefaultFilter()

	// Without intent -> should ask immediately
	callWithoutIntent := &harness.NormalizedToolCall{
		ToolName:   "write_to_file",
		TargetPath: ".env",
		UserIntent: "",
	}
	resAsk := filter.Evaluate(callWithoutIntent)
	if resAsk == nil || resAsk.Decision != harness.DecisionAsk {
		t.Fatalf("expected ASK for .env without intent, got %+v", resAsk)
	}

	// With intent -> should defer (return nil) to semantic evaluation
	callWithIntent := &harness.NormalizedToolCall{
		ToolName:   "write_to_file",
		TargetPath: ".env",
		UserIntent: "Configure DATABASE_URL in .env",
	}
	resDefer := filter.Evaluate(callWithIntent)
	if resDefer != nil {
		t.Fatalf("expected nil (deferred to Jev) when intent is present, got %+v", resDefer)
	}
}

