package fastpath

import (
	"fmt"
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

	// Windows backslash path to .ssh and .aws
	callWinSSH := &harness.NormalizedToolCall{
		ToolName:   "view_file",
		TargetPath: `C:\Users\User\.ssh\config`,
	}
	resWinSSH := filter.Evaluate(callWinSSH)
	if resWinSSH == nil || resWinSSH.Decision != harness.DecisionAsk {
		t.Errorf("expected ASK for Windows .ssh path, got %+v", resWinSSH)
	}

	callWinAWS := &harness.NormalizedToolCall{
		ToolName: "run_command",
		Command:  `type C:\Users\User\.aws\credentials`,
	}
	resWinAWS := filter.Evaluate(callWinAWS)
	if resWinAWS == nil || resWinAWS.Decision != harness.DecisionAsk {
		t.Errorf("expected ASK for Windows .aws path, got %+v", resWinAWS)
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
	chainedCommands := []string{
		"git status; rm -rf /",
		"git status && rm -rf /",
		"git status & rm -rf /",
		"git status\nrm -rf /",
		"git status \n rm -rf /",
		"git status\r\nrm -rf /",
		"git status | grep foo",
		"git status > out.txt",
		"echo (Get-Process)",
		"git status (calc)",
		"git status $(whoami)",
		"echo { dangerous }",
		"ls < input.txt",
	}
	for _, chainedCmd := range chainedCommands {
		callChained := &harness.NormalizedToolCall{
			ToolName: "run_command",
			Command:  chainedCmd,
		}
		if resChained := filter.Evaluate(callChained); resChained != nil {
			t.Errorf("expected nil (delegation to Jev) for chained command %q, got %+v", chainedCmd, resChained)
		}
	}
}

func TestFastPath_ReadUrlContent_DelegatesToSemantic(t *testing.T) {
	filter := NewDefaultFilter()

	call := &harness.NormalizedToolCall{
		ToolName:   "read_url_content",
		TargetPath: "https://example.com/docs",
	}
	res := filter.Evaluate(call)
	if res != nil {
		t.Errorf("expected nil (pass-through to semantic evaluator for outbound HTTP fetch), got %+v", res)
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
	err       error
}

func (m *mockBoundaryChecker) IsPathContained(targetPath string, cwd string) (bool, error) {
	return m.contained, m.err
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

	// Resolution error must fail closed (DecisionAsk)
	checker.err = fmt.Errorf("canonicalization failed")
	resErr := filter.Evaluate(call)
	if resErr == nil || resErr.Decision != harness.DecisionAsk {
		t.Fatalf("expected ASK on boundary checker error (fail-closed), got %+v", resErr)
	}

	checker.err = nil
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

	callRelTarget := &harness.NormalizedToolCall{
		ToolName:   "write_to_file",
		TargetPath: ".jevguard/sessions/malicious.json",
	}
	resRelTarget := filter.Evaluate(callRelTarget)
	if resRelTarget == nil || resRelTarget.Decision != harness.DecisionDeny {
		t.Fatalf("expected DENY for relative path targeting .jevguard, got %+v", resRelTarget)
	}

	callConfig := &harness.NormalizedToolCall{
		ToolName:   "view_file",
		TargetPath: ".jevguard.json",
	}
	resConfig := filter.Evaluate(callConfig)
	if resConfig == nil || resConfig.Decision != harness.DecisionDeny {
		t.Fatalf("expected DENY for reading .jevguard.json, got %+v", resConfig)
	}

	callConfigAlt := &harness.NormalizedToolCall{
		ToolName:   "read_file",
		TargetPath: "jevguard.json",
	}
	resConfigAlt := filter.Evaluate(callConfigAlt)
	if resConfigAlt == nil || resConfigAlt.Decision != harness.DecisionDeny {
		t.Fatalf("expected DENY for reading jevguard.json, got %+v", resConfigAlt)
	}
}

func TestFastPath_SensitiveFiles_WithIntentDefers(t *testing.T) {
	filter := NewDefaultFilter()

	// Without intent -> should ask immediately for write
	callWithoutIntent := &harness.NormalizedToolCall{
		ToolName:   "write_to_file",
		TargetPath: ".env",
		UserIntent: "",
	}
	resAsk := filter.Evaluate(callWithoutIntent)
	if resAsk == nil || resAsk.Decision != harness.DecisionAsk {
		t.Fatalf("expected ASK for write_to_file .env without intent, got %+v", resAsk)
	}

	// Without intent -> should ask immediately for read tools (view_file)
	callReadWithoutIntent := &harness.NormalizedToolCall{
		ToolName:   "view_file",
		TargetPath: ".env",
		UserIntent: "",
	}
	resReadAsk := filter.Evaluate(callReadWithoutIntent)
	if resReadAsk == nil || resReadAsk.Decision != harness.DecisionAsk {
		t.Fatalf("expected ASK for view_file .env without intent, got %+v", resReadAsk)
	}

	// Without intent -> should ask immediately for trusted read command (cat .env)
	callCmdWithoutIntent := &harness.NormalizedToolCall{
		ToolName:   "run_command",
		Command:    "cat .env",
		UserIntent: "",
	}
	resCmdAsk := filter.Evaluate(callCmdWithoutIntent)
	if resCmdAsk == nil || resCmdAsk.Decision != harness.DecisionAsk {
		t.Fatalf("expected ASK for cat .env without intent, got %+v", resCmdAsk)
	}

	// With intent -> should defer (return nil) for write
	callWithIntent := &harness.NormalizedToolCall{
		ToolName:   "write_to_file",
		TargetPath: ".env",
		UserIntent: "Configure DATABASE_URL in .env",
	}
	resDefer := filter.Evaluate(callWithIntent)
	if resDefer != nil {
		t.Fatalf("expected nil (deferred to Jev) for write with intent, got %+v", resDefer)
	}

	// With intent -> should defer (return nil) for view_file, NEVER auto-allow
	callReadWithIntent := &harness.NormalizedToolCall{
		ToolName:   "view_file",
		TargetPath: ".env",
		UserIntent: "Inspect database configuration",
	}
	resReadDefer := filter.Evaluate(callReadWithIntent)
	if resReadDefer != nil {
		t.Fatalf("expected nil (deferred to Jev) for view_file with intent, got %+v", resReadDefer)
	}

	// With intent -> should defer (return nil) for trusted command (cat .env), NEVER auto-allow
	callCmdWithIntent := &harness.NormalizedToolCall{
		ToolName:   "run_command",
		Command:    "cat .env",
		UserIntent: "Inspect database configuration",
	}
	resCmdDefer := filter.Evaluate(callCmdWithIntent)
	if resCmdDefer != nil {
		t.Fatalf("expected nil (deferred to Jev) for cat .env with intent, got %+v", resCmdDefer)
	}
}

func TestFastPath_SensitiveFiles_Globs(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.SensitiveFiles = []string{"*.pem", "*.key"}
	filter := NewFilter(nil, cfg)

	// Target path glob
	call1 := &harness.NormalizedToolCall{
		ToolName:   "view_file",
		TargetPath: "certs/server.pem",
	}
	res1 := filter.Evaluate(call1)
	if res1 == nil || res1.Decision != harness.DecisionAsk {
		t.Fatalf("expected ASK for glob *.pem on server.pem, got %+v", res1)
	}

	// Command argument glob
	call2 := &harness.NormalizedToolCall{
		ToolName: "Bash",
		Command:  "openssl x509 -in cert.pem -text",
	}
	res2 := filter.Evaluate(call2)
	if res2 == nil || res2.Decision != harness.DecisionAsk {
		t.Fatalf("expected ASK for glob *.pem in command args, got %+v", res2)
	}
}

func TestFastPath_TrustedCommands_ArgumentEscape(t *testing.T) {
	checker := &mockBoundaryChecker{contained: false}
	filter := NewFilter(checker, nil)

	call1 := &harness.NormalizedToolCall{
		ToolName: "run_command",
		Command:  "ls /etc",
	}
	res1 := filter.Evaluate(call1)
	if res1 != nil {
		t.Errorf("expected nil (delegation) for 'ls /etc' escaping boundary, got %+v", res1)
	}

	call2 := &harness.NormalizedToolCall{
		ToolName: "run_command",
		Command:  "git diff ../../other_repo",
	}
	res2 := filter.Evaluate(call2)
	if res2 != nil {
		t.Errorf("expected nil (delegation) for 'git diff ../../other_repo' escaping boundary, got %+v", res2)
	}

	// Contained argument should be allowed
	checker.contained = true
	call3 := &harness.NormalizedToolCall{
		ToolName: "run_command",
		Command:  "git diff HEAD~1",
	}
	res3 := filter.Evaluate(call3)
	if res3 == nil || res3.Decision != harness.DecisionAllow {
		t.Errorf("expected ALLOW for contained git diff, got %+v", res3)
	}

	// Output writing flags must be rejected (deferred to semantic evaluation)
	callOutputFlag := &harness.NormalizedToolCall{
		ToolName: "run_command",
		Command:  "git diff --output=diff.txt",
	}
	if resOut := filter.Evaluate(callOutputFlag); resOut != nil {
		t.Errorf("expected nil (delegation) for git diff with --output flag, got %+v", resOut)
	}

	callOFlag := &harness.NormalizedToolCall{
		ToolName: "run_command",
		Command:  "git diff -o out.patch",
	}
	if resO := filter.Evaluate(callOFlag); resO != nil {
		t.Errorf("expected nil (delegation) for git diff with -o flag, got %+v", resO)
	}

	// Flag with path escaping boundary
	checker.contained = false
	callFlagEscape := &harness.NormalizedToolCall{
		ToolName: "run_command",
		Command:  "git log --file=../../outside.txt",
	}
	if resFlagEsc := filter.Evaluate(callFlagEscape); resFlagEsc != nil {
		t.Errorf("expected nil (delegation) for git log with escaping --file=... argument, got %+v", resFlagEsc)
	}
}


