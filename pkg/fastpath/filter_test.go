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
	filter := NewFilter(&mockBoundaryChecker{contained: true}, config.DefaultConfig())

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
	} else if resWinSSH.Source != "fastpath_sensitive" {
		t.Errorf("expected sensitive-file match for Windows .ssh path, got source %q", resWinSSH.Source)
	}

	callWinAWS := &harness.NormalizedToolCall{
		ToolName: "run_command",
		Command:  `type C:\Users\User\.aws\credentials`,
	}
	resWinAWS := filter.Evaluate(callWinAWS)
	if resWinAWS == nil || resWinAWS.Decision != harness.DecisionAsk {
		t.Errorf("expected ASK for Windows .aws path, got %+v", resWinAWS)
	} else if resWinAWS.Source != "fastpath_sensitive" {
		t.Errorf("expected sensitive-file match for Windows .aws path, got source %q", resWinAWS.Source)
	}
}

func TestFastPath_SensitiveFiles_DockerAndGitconfig(t *testing.T) {
	filter := NewFilter(&mockBoundaryChecker{contained: true}, config.DefaultConfig())

	flagged := []struct {
		name string
		path string
	}{
		{"windows docker config", `C:\Users\u\.docker\config.json`},
		{"posix docker config", "/home/u/.docker/config.json"},
		{"posix gitconfig", "/home/u/.gitconfig"},
	}
	for _, tc := range flagged {
		res := filter.Evaluate(&harness.NormalizedToolCall{ToolName: "view_file", TargetPath: tc.path})
		if res == nil || res.Decision != harness.DecisionAsk || res.Source != "fastpath_sensitive" {
			t.Errorf("%s (%s): expected sensitive-file ASK, got %+v", tc.name, tc.path, res)
		}
	}

	res := filter.Evaluate(&harness.NormalizedToolCall{ToolName: "view_file", TargetPath: "/home/u/project/config.json"})
	if res != nil && res.Source == "fastpath_sensitive" {
		t.Errorf("expected generic config.json NOT to be flagged sensitive, got %+v", res)
	}
}

func assertSensitiveAsk(t *testing.T, filter *Filter, name string, call *harness.NormalizedToolCall) {
	t.Helper()
	res := filter.Evaluate(call)
	if res == nil {
		t.Errorf("%s: expected decision %q with source %q, got nil", name, harness.DecisionAsk, "fastpath_sensitive")
		return
	}
	if res.Decision != harness.DecisionAsk || res.Source != "fastpath_sensitive" {
		t.Errorf("%s: expected decision %q with source %q, got decision %q with source %q", name, harness.DecisionAsk, "fastpath_sensitive", res.Decision, res.Source)
	}
}

// assertTrustedAllow is the non-sensitive control: an ordinary read of a
// contained file must reach the trusted fast path rather than the sensitive check.
func assertTrustedAllow(t *testing.T, filter *Filter, name string, call *harness.NormalizedToolCall) {
	t.Helper()
	res := filter.Evaluate(call)
	if res == nil {
		t.Errorf("%s: expected decision %q with source %q, got nil", name, harness.DecisionAllow, "fastpath_trusted")
		return
	}
	if res.Decision != harness.DecisionAllow || res.Source != "fastpath_trusted" {
		t.Errorf("%s: expected decision %q with source %q, got decision %q with source %q", name, harness.DecisionAllow, "fastpath_trusted", res.Decision, res.Source)
	}
}

// assertDeferred is the non-sensitive control for commands outside the trusted
// cache: the fast path must return nil so semantic evaluation decides.
func assertDeferred(t *testing.T, filter *Filter, name string, call *harness.NormalizedToolCall) {
	t.Helper()
	if res := filter.Evaluate(call); res != nil {
		t.Errorf("%s: expected nil (deferred to semantic evaluation), got decision %q with source %q", name, res.Decision, res.Source)
	}
}

func TestFastPath_SensitiveFiles_DockerAndGitconfigCommandAccess(t *testing.T) {
	filter := NewFilter(&mockBoundaryChecker{contained: true}, config.DefaultConfig())

	for _, tc := range []struct {
		name    string
		tool    string
		command string
	}{
		{"posix gitconfig command", "Bash", "cat ~/.gitconfig"},
		{"posix docker config command", "Bash", "cat ~/.docker/config.json"},
		{"windows gitconfig command", "run_command", `type C:\Users\u\.gitconfig`},
		{"windows docker config command", "run_command", `type C:\Users\u\.docker\config.json`},
		{"trusted ls of gitconfig", "Bash", "ls ~/.gitconfig"},
		{"trusted ls of docker config", "Bash", "ls ~/.docker/config.json"},
	} {
		assertSensitiveAsk(t, filter, tc.name, &harness.NormalizedToolCall{ToolName: tc.tool, Command: tc.command})
	}

	assertSensitiveAsk(t, filter, "windows gitconfig target", &harness.NormalizedToolCall{ToolName: "view_file", TargetPath: `C:\Users\u\.gitconfig`})

	assertDeferred(t, filter, "ordinary config.json command", &harness.NormalizedToolCall{ToolName: "Bash", Command: "cat config.json"})
	assertTrustedAllow(t, filter, "trusted ls of ordinary config.json", &harness.NormalizedToolCall{ToolName: "Bash", Command: "ls config.json"})
	assertTrustedAllow(t, filter, "ordinary config.json target", &harness.NormalizedToolCall{ToolName: "view_file", TargetPath: "/home/u/project/config.json"})
}

func TestFastPath_SensitiveFiles_GitXDGConfig(t *testing.T) {
	filter := NewFilter(&mockBoundaryChecker{contained: true}, config.DefaultConfig())

	for _, tc := range []struct {
		name string
		path string
	}{
		{"posix xdg git config", "/home/u/.config/git/config"},
		{"posix xdg git credentials", "/home/u/.config/git/credentials"},
		{"windows xdg git config", `C:\Users\u\.config\git\config`},
		{"windows xdg git credentials", `C:\Users\u\.config\git\credentials`},
	} {
		assertSensitiveAsk(t, filter, tc.name+" target", &harness.NormalizedToolCall{ToolName: "view_file", TargetPath: tc.path})
	}

	for _, tc := range []struct {
		name    string
		tool    string
		command string
	}{
		{"posix xdg git config", "Bash", "cat ~/.config/git/config"},
		{"posix xdg git credentials", "Bash", "cat ~/.config/git/credentials"},
		{"windows xdg git config", "run_command", `type C:\Users\u\.config\git\config`},
		{"windows xdg git credentials", "run_command", `type C:\Users\u\.config\git\credentials`},
		{"trusted ls of xdg git credentials", "Bash", "ls ~/.config/git/credentials"},
	} {
		assertSensitiveAsk(t, filter, tc.name+" command", &harness.NormalizedToolCall{ToolName: tc.tool, Command: tc.command})
	}

	assertTrustedAllow(t, filter, "ordinary xdg config.json target", &harness.NormalizedToolCall{ToolName: "view_file", TargetPath: "/home/u/.config/app/config.json"})
	assertDeferred(t, filter, "ordinary xdg config.json command", &harness.NormalizedToolCall{ToolName: "Bash", Command: "cat ~/.config/app/config.json"})
}

func TestFastPath_SensitiveFiles_CustomXDGConfigHome(t *testing.T) {
	t.Run("posix absolute", func(t *testing.T) {
		for _, dir := range []string{"/srv/xdg", "/srv/xdg/"} {
			t.Setenv("XDG_CONFIG_HOME", dir)
			filter := NewFilter(&mockBoundaryChecker{contained: true}, config.DefaultConfig())

			assertSensitiveAsk(t, filter, dir+" config target", &harness.NormalizedToolCall{ToolName: "view_file", TargetPath: "/srv/xdg/git/config"})
			assertSensitiveAsk(t, filter, dir+" credentials target", &harness.NormalizedToolCall{ToolName: "view_file", TargetPath: "/srv/xdg/git/credentials"})
			assertSensitiveAsk(t, filter, dir+" config command", &harness.NormalizedToolCall{ToolName: "Bash", Command: "cat /srv/xdg/git/config"})
			assertSensitiveAsk(t, filter, dir+" credentials command", &harness.NormalizedToolCall{ToolName: "Bash", Command: "cat /srv/xdg/git/credentials"})
		}
	})

	t.Run("windows absolute", func(t *testing.T) {
		t.Setenv("XDG_CONFIG_HOME", `D:\xdg`)
		filter := NewFilter(&mockBoundaryChecker{contained: true}, config.DefaultConfig())

		assertSensitiveAsk(t, filter, "windows credentials target", &harness.NormalizedToolCall{ToolName: "view_file", TargetPath: `D:\xdg\git\credentials`})
		assertSensitiveAsk(t, filter, "windows config command", &harness.NormalizedToolCall{ToolName: "run_command", Command: `type D:\xdg\git\config`})
	})

	t.Run("controls with custom home", func(t *testing.T) {
		t.Setenv("XDG_CONFIG_HOME", "/srv/xdg")
		filter := NewFilter(&mockBoundaryChecker{contained: true}, config.DefaultConfig())

		assertTrustedAllow(t, filter, "ordinary app config target", &harness.NormalizedToolCall{ToolName: "view_file", TargetPath: "/srv/xdg/app/config.json"})
		assertDeferred(t, filter, "ordinary app config command", &harness.NormalizedToolCall{ToolName: "Bash", Command: "cat /srv/xdg/app/config.json"})
	})

	t.Run("relative value ignored", func(t *testing.T) {
		t.Setenv("XDG_CONFIG_HOME", "xdg")
		filter := NewFilter(&mockBoundaryChecker{contained: true}, config.DefaultConfig())

		assertTrustedAllow(t, filter, "relative xdg git config target", &harness.NormalizedToolCall{ToolName: "view_file", TargetPath: "/home/u/project/xdg/git/config"})
	})

	t.Run("unset or empty", func(t *testing.T) {
		t.Setenv("XDG_CONFIG_HOME", "")
		filter := NewFilter(&mockBoundaryChecker{contained: true}, config.DefaultConfig())

		assertTrustedAllow(t, filter, "empty xdg git config target", &harness.NormalizedToolCall{ToolName: "view_file", TargetPath: "/srv/xdg/git/config"})
		assertSensitiveAsk(t, filter, "static default credentials target", &harness.NormalizedToolCall{ToolName: "view_file", TargetPath: "/home/u/.config/git/credentials"})
	})

	t.Run("unexpanded variable references", func(t *testing.T) {
		t.Setenv("XDG_CONFIG_HOME", "")
		filter := NewFilter(&mockBoundaryChecker{contained: true}, config.DefaultConfig())

		assertSensitiveAsk(t, filter, "posix $VAR credentials", &harness.NormalizedToolCall{ToolName: "Bash", Command: "cat $XDG_CONFIG_HOME/git/credentials"})
		assertSensitiveAsk(t, filter, "posix ${VAR} config", &harness.NormalizedToolCall{ToolName: "Bash", Command: "cat ${XDG_CONFIG_HOME}/git/config"})
		assertSensitiveAsk(t, filter, "cmd %VAR% credentials", &harness.NormalizedToolCall{ToolName: "run_command", Command: `type %XDG_CONFIG_HOME%\git\credentials`})
		assertSensitiveAsk(t, filter, "powershell $env:VAR config", &harness.NormalizedToolCall{ToolName: "run_command", Command: `Get-Content $env:XDG_CONFIG_HOME\git\config`})
	})
}

func TestNormalizePathSeparators(t *testing.T) {
	got := normalizePathSeparators(`C:\Users\User\.aws\credentials`)
	want := "C:/Users/User/.aws/credentials"
	if got != want {
		t.Errorf("normalizePathSeparators() = %q, want %q", got, want)
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

func TestFastPath_ReadResource_FileURIs(t *testing.T) {
	checker := &mockBoundaryChecker{contained: true}
	filter := NewFilter(checker, nil)

	// Contained file URI
	callContained := &harness.NormalizedToolCall{
		ToolName:   "read_resource",
		TargetPath: "file:///workspace/project/data.json",
	}
	resContained := filter.Evaluate(callContained)
	if resContained == nil || resContained.Decision != harness.DecisionAllow {
		t.Fatalf("expected ALLOW for contained file URI, got %+v", resContained)
	}

	// Escaping file URI
	checker.contained = false
	callEscape := &harness.NormalizedToolCall{
		ToolName:   "read_resource",
		TargetPath: "file:///C:/Windows/system.ini",
	}
	resEscape := filter.Evaluate(callEscape)
	if resEscape == nil || resEscape.Decision != harness.DecisionAsk {
		t.Fatalf("expected ASK for escaping file URI, got %+v", resEscape)
	}

	// Non-file custom URI (e.g. database/external resource) must defer to semantic evaluation
	callExternal := &harness.NormalizedToolCall{
		ToolName:   "read_resource",
		TargetPath: "postgres://db.internal/secrets",
	}
	if resExt := filter.Evaluate(callExternal); resExt != nil {
		t.Fatalf("expected nil (delegation to Jev) for external URI, got %+v", resExt)
	}
}

func TestFastPath_ClaudeToolCoverage(t *testing.T) {
	filter := NewDefaultFilter()

	if res := filter.Evaluate(&harness.NormalizedToolCall{ToolName: "Read", TargetPath: "pkg/fastpath/filter.go", WorkspaceRoots: []string{"."}}); res == nil || res.Decision != harness.DecisionAllow {
		t.Errorf("expected ALLOW for in-workspace Read, got %+v", res)
	}
	if res := filter.Evaluate(&harness.NormalizedToolCall{ToolName: "Read", TargetPath: ".env", WorkspaceRoots: []string{"."}}); res == nil || res.Decision == harness.DecisionAllow {
		t.Errorf("expected non-ALLOW for Read of .env, got %+v", res)
	}
	if res := filter.Evaluate(&harness.NormalizedToolCall{ToolName: "PowerShell", Command: "echo (Remove-Item x)", WorkspaceRoots: []string{"."}}); res != nil && res.Decision == harness.DecisionAllow {
		t.Errorf("PowerShell subexpression must not be fastpath allowed, got %+v", res)
	}
	if res := filter.Evaluate(&harness.NormalizedToolCall{ToolName: "WebFetch", TargetPath: "https://example.com", WorkspaceRoots: []string{"."}}); res != nil {
		t.Errorf("WebFetch must defer to semantic evaluation, got %+v", res)
	}
}

// Repository-local .git/config policy (#30): any direct access to the file, by a file
// tool or by a command that names it, asks for confirmation regardless of content.
// Pre-tool hooks cannot see what a read will return, and writes can set
// command-executing keys, so credential-free configuration is not exempt.
func TestFastPath_RepoGitConfig_DirectAccessAsks(t *testing.T) {
	filter := NewFilter(&mockBoundaryChecker{contained: true}, config.DefaultConfig())
	const wantReason = "Access to sensitive file or credential pattern: .git/config"

	cases := []struct {
		name string
		call harness.NormalizedToolCall
	}{
		{"read posix absolute", harness.NormalizedToolCall{ToolName: "Read", TargetPath: "/home/u/repo/.git/config"}},
		{"read relative", harness.NormalizedToolCall{ToolName: "view_file", TargetPath: ".git/config"}},
		{"read windows separators", harness.NormalizedToolCall{ToolName: "view_file", TargetPath: `C:\Users\u\repo\.git\config`}},
		{"read windows mixed case", harness.NormalizedToolCall{ToolName: "read_file", TargetPath: `C:\Users\u\Repo\.GIT\Config`}},
		{"read file uri", harness.NormalizedToolCall{ToolName: "read_resource", TargetPath: "file:///home/u/repo/.git/config"}},
		{"read bare repository config", harness.NormalizedToolCall{ToolName: "Read", TargetPath: "/srv/git/repo.git/config"}},
		{"write credential-bearing remote", harness.NormalizedToolCall{
			ToolName:   "Write",
			TargetPath: "/home/u/repo/.git/config",
			RawArgs:    map[string]interface{}{"content": "[remote \"origin\"]\n\turl = https://user:ghp_token@github.com/o/r.git\n"},
		}},
		{"write ordinary config", harness.NormalizedToolCall{
			ToolName:   "Write",
			TargetPath: "/home/u/repo/.git/config",
			RawArgs:    map[string]interface{}{"content": "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"},
		}},
		{"edit windows separators", harness.NormalizedToolCall{ToolName: "Edit", TargetPath: `D:\work\repo\.git\config`}},
		{"cat posix", harness.NormalizedToolCall{ToolName: "Bash", Command: "cat .git/config"}},
		{"type windows", harness.NormalizedToolCall{ToolName: "run_command", Command: `type .git\config`}},
		{"powershell windows absolute", harness.NormalizedToolCall{ToolName: "PowerShell", Command: `Get-Content C:\Users\u\repo\.git\config`}},
		{"git config with explicit file", harness.NormalizedToolCall{ToolName: "Bash", Command: "git config --file .git/config --list"}},
		{"trusted prefix naming the file", harness.NormalizedToolCall{ToolName: "Bash", Command: "git log -- .git/config"}},
		{"sed writing credential url", harness.NormalizedToolCall{ToolName: "Bash", Command: `sed -i "s#url = .*#url = https://user:token@example.com/r.git#" .git/config`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			call := tc.call
			res := filter.Evaluate(&call)
			if res == nil {
				t.Fatalf("expected fastpath_sensitive ASK, got nil")
			}
			if res.Decision != harness.DecisionAsk || res.Source != "fastpath_sensitive" || res.Reason != wantReason {
				t.Errorf("got decision=%q source=%q reason=%q; want %q %q %q",
					res.Decision, res.Source, res.Reason, harness.DecisionAsk, "fastpath_sensitive", wantReason)
			}
		})
	}
}

// Git CLI usage that does not name the file is outside the sensitive-file rule.
// It is not a trusted command, so it defers to semantic evaluation (nil) rather than
// being auto-allowed or prompted by the fast path.
func TestFastPath_RepoGitConfig_CLIWithoutPathDefers(t *testing.T) {
	filter := NewFilter(&mockBoundaryChecker{contained: true}, config.DefaultConfig())

	for _, cmd := range []string{
		"git config --get remote.origin.url",
		"git config --local --list",
		"git remote -v",
		"git remote set-url origin https://github.com/o/r.git",
	} {
		if res := filter.Evaluate(&harness.NormalizedToolCall{ToolName: "Bash", Command: cmd}); res != nil {
			t.Errorf("%q: expected nil (semantic evaluation), got %+v", cmd, res)
		}
	}
}

func TestFastPath_RepoGitConfig_LookalikePathsNotSensitive(t *testing.T) {
	filter := NewFilter(&mockBoundaryChecker{contained: true}, config.DefaultConfig())

	for _, target := range []string{
		"/home/u/repo/.github/config.yml",
		"/home/u/repo/internal/git/config.go",
		`C:\Users\u\repo\config\git.yaml`,
	} {
		res := filter.Evaluate(&harness.NormalizedToolCall{ToolName: "Read", TargetPath: target})
		if res == nil || res.Decision != harness.DecisionAllow || res.Source != "fastpath_trusted" {
			t.Errorf("%s: expected fastpath_trusted ALLOW, got %+v", target, res)
		}
	}
}

func TestFastPath_RepoGitConfig_UserIntentDefersToSemantic(t *testing.T) {
	filter := NewFilter(&mockBoundaryChecker{contained: true}, config.DefaultConfig())

	res := filter.Evaluate(&harness.NormalizedToolCall{
		ToolName:   "Read",
		TargetPath: "/home/u/repo/.git/config",
		UserIntent: "show me which remote this repository pushes to",
	})
	if res != nil {
		t.Errorf("expected nil (semantic intent verification), got %+v", res)
	}
}

// Git config files inside submodule Git directories (.git/modules/<name...>/) are not
// covered by the ".git/config" pattern and are reported with the repository Git config reason.
func TestFastPath_RepoGitConfig_SubmoduleConfigsAsk(t *testing.T) {
	filter := NewFilter(&mockBoundaryChecker{contained: true}, config.DefaultConfig())
	const wantReason = "Access to repository Git config file"

	cases := []struct {
		name string
		call harness.NormalizedToolCall
	}{
		{"read submodule config", harness.NormalizedToolCall{ToolName: "Read", TargetPath: "/home/u/repo/.git/modules/lib/config"}},
		{"read nested submodule config", harness.NormalizedToolCall{ToolName: "Read", TargetPath: "/home/u/repo/.git/modules/a/modules/b/config"}},
		{"read submodule name with slash", harness.NormalizedToolCall{ToolName: "Read", TargetPath: "/home/u/repo/.git/modules/vendor/lib/config"}},
		{"read windows submodule config", harness.NormalizedToolCall{ToolName: "Read", TargetPath: `C:\Users\u\repo\.git\modules\lib\config`}},
		{"read windows mixed case submodule config", harness.NormalizedToolCall{ToolName: "Read", TargetPath: `C:\Repo\.GIT\Modules\Lib\CONFIG`}},
		{"write submodule config.worktree", harness.NormalizedToolCall{ToolName: "Write", TargetPath: "/home/u/repo/.git/modules/lib/config.worktree"}},
		{"cat submodule config", harness.NormalizedToolCall{ToolName: "Bash", Command: "cat .git/modules/lib/config"}},
		{"type windows submodule config", harness.NormalizedToolCall{ToolName: "run_command", Command: `type .git\modules\lib\config`}},
		{"git config file flag submodule config", harness.NormalizedToolCall{ToolName: "Bash", Command: "git config --file=.git/modules/lib/config --list"}},
		{"read submodule config file uri", harness.NormalizedToolCall{ToolName: "read_resource", TargetPath: "file:///home/u/repo/.git/modules/lib/config"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			call := tc.call
			res := filter.Evaluate(&call)
			if res == nil {
				t.Fatalf("expected fastpath_sensitive ASK, got nil")
			}
			if res.Decision != harness.DecisionAsk || res.Source != "fastpath_sensitive" || res.Reason != wantReason {
				t.Errorf("got decision=%q source=%q reason=%q; want %q %q %q",
					res.Decision, res.Source, res.Reason, harness.DecisionAsk, "fastpath_sensitive", wantReason)
			}
		})
	}
}

// Worktree-specific configs. Paths containing ".git/config" as a substring (config.worktree
// directly under .git) match the earlier sensitive pattern first and keep its reason; paths
// under .git/worktrees/<name>/ are reported with the repository Git config reason.
func TestFastPath_RepoGitConfig_WorktreeConfigsAsk(t *testing.T) {
	filter := NewFilter(&mockBoundaryChecker{contained: true}, config.DefaultConfig())
	const patternReason = "Access to sensitive file or credential pattern: .git/config"
	const wantReason = "Access to repository Git config file"

	cases := []struct {
		name       string
		call       harness.NormalizedToolCall
		wantReason string
	}{
		{"read git dir config.worktree", harness.NormalizedToolCall{ToolName: "Read", TargetPath: "/home/u/repo/.git/config.worktree"}, patternReason},
		{"read windows git dir config.worktree", harness.NormalizedToolCall{ToolName: "Read", TargetPath: `C:\repo\.git\config.worktree`}, patternReason},
		{"read worktree config.worktree", harness.NormalizedToolCall{ToolName: "Read", TargetPath: "/home/u/repo/.git/worktrees/feature/config.worktree"}, wantReason},
		{"read windows worktree config.worktree", harness.NormalizedToolCall{ToolName: "Read", TargetPath: `C:\repo\.git\worktrees\feature\config.worktree`}, wantReason},
		{"cat worktree config.worktree", harness.NormalizedToolCall{ToolName: "Bash", Command: "cat .git/worktrees/feature/config.worktree"}, wantReason},
		{"edit windows worktree config.worktree", harness.NormalizedToolCall{ToolName: "Edit", TargetPath: `D:\w\repo\.git\worktrees\feature\config.worktree`}, wantReason},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			call := tc.call
			res := filter.Evaluate(&call)
			if res == nil {
				t.Fatalf("expected fastpath_sensitive ASK, got nil")
			}
			if res.Decision != harness.DecisionAsk || res.Source != "fastpath_sensitive" || res.Reason != tc.wantReason {
				t.Errorf("got decision=%q source=%q reason=%q; want %q %q %q",
					res.Decision, res.Source, res.Reason, harness.DecisionAsk, "fastpath_sensitive", tc.wantReason)
			}
		})
	}
}

// Relative paths that only resolve into a Git directory once joined with Cwd are reported
// with the repository Git config reason.
func TestFastPath_RepoGitConfig_RelativeFromGitDirAsks(t *testing.T) {
	filter := NewFilter(&mockBoundaryChecker{contained: true}, config.DefaultConfig())
	const wantReason = "Access to repository Git config file"

	cases := []struct {
		name string
		call harness.NormalizedToolCall
	}{
		{"read config from git dir", harness.NormalizedToolCall{ToolName: "Read", TargetPath: "config", Cwd: "/home/u/repo/.git"}},
		{"read config from windows git dir", harness.NormalizedToolCall{ToolName: "Read", TargetPath: "config", Cwd: `C:\Users\u\repo\.git`}},
		{"read config.worktree from git dir", harness.NormalizedToolCall{ToolName: "Read", TargetPath: "config.worktree", Cwd: "/home/u/repo/.git"}},
		{"read config from submodule git dir", harness.NormalizedToolCall{ToolName: "Read", TargetPath: "config", Cwd: "/home/u/repo/.git/modules/lib"}},
		{"read parent config from hooks dir", harness.NormalizedToolCall{ToolName: "Read", TargetPath: "../config", Cwd: "/home/u/repo/.git/hooks"}},
		{"cat config from git dir", harness.NormalizedToolCall{ToolName: "Bash", Command: "cat config", Cwd: "/home/u/repo/.git"}},
		{"type config from windows git dir", harness.NormalizedToolCall{ToolName: "run_command", Command: "type config", Cwd: `C:\repo\.git`}},
		{"read config from bare repository", harness.NormalizedToolCall{ToolName: "Read", TargetPath: "config", Cwd: "/srv/git/repo.git"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			call := tc.call
			res := filter.Evaluate(&call)
			if res == nil {
				t.Fatalf("expected fastpath_sensitive ASK, got nil")
			}
			if res.Decision != harness.DecisionAsk || res.Source != "fastpath_sensitive" || res.Reason != wantReason {
				t.Errorf("got decision=%q source=%q reason=%q; want %q %q %q",
					res.Decision, res.Source, res.Reason, harness.DecisionAsk, "fastpath_sensitive", wantReason)
			}
		})
	}
}

// Paths and commands that look structurally similar to repository Git config files but are
// not one must not be classified as fastpath_sensitive.
func TestFastPath_RepoGitConfig_StructuralLookalikesNotSensitive(t *testing.T) {
	filter := NewFilter(&mockBoundaryChecker{contained: true}, config.DefaultConfig())

	cases := []struct {
		name string
		call harness.NormalizedToolCall
	}{
		{"config relative to work tree", harness.NormalizedToolCall{ToolName: "Read", TargetPath: "config", Cwd: "/home/u/repo"}},
		{"modules config too shallow", harness.NormalizedToolCall{ToolName: "Read", TargetPath: "/home/u/repo/.git/modules/config"}},
		{"worktree config not config.worktree", harness.NormalizedToolCall{ToolName: "Read", TargetPath: "/home/u/repo/.git/worktrees/feature/config"}},
		{"git hooks file", harness.NormalizedToolCall{ToolName: "Read", TargetPath: "/home/u/repo/.git/hooks/pre-commit"}},
		{"modules directory outside git dir", harness.NormalizedToolCall{ToolName: "Read", TargetPath: "/home/u/repo/src/modules/lib/config"}},
		{"git subcommand is not a file argument", harness.NormalizedToolCall{ToolName: "Bash", Command: "git config --list", Cwd: "/home/u/repo/.git"}},
		{"cat readme from git dir", harness.NormalizedToolCall{ToolName: "Bash", Command: "cat README.md", Cwd: "/home/u/repo/.git"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			call := tc.call
			res := filter.Evaluate(&call)
			if res != nil && res.Source == "fastpath_sensitive" {
				t.Errorf("expected not fastpath_sensitive, got %+v", res)
			}
		})
	}
}

func TestFastPath_RepoGitConfig_QuotedCommands(t *testing.T) {
	filter := NewFilter(&mockBoundaryChecker{contained: true}, config.DefaultConfig())
	for _, command := range []string{
		`ls ".git/modules/my module/config"`,
		`cat '.git/worktrees/my branch/config.worktree'`,
		`git config --file=".git/modules/my module/config" --list`,
		`type "C:\my repo\.git\modules\my module\config"`,
	} {
		call := &harness.NormalizedToolCall{ToolName: "Bash", Command: command}
		res := filter.Evaluate(call)
		if res == nil || res.Decision != harness.DecisionAsk || res.Source != "fastpath_sensitive" {
			t.Errorf("%q: expected sensitive ASK, got %+v", command, res)
		}
	}
}

func TestFastPath_RepoGitConfig_GitNamedArgument(t *testing.T) {
	filter := NewFilter(&mockBoundaryChecker{contained: true}, config.DefaultConfig())
	call := &harness.NormalizedToolCall{ToolName: "Bash", Command: "ls git config", Cwd: "/repo/.git"}
	res := filter.Evaluate(call)
	if res == nil || res.Decision != harness.DecisionAsk || res.Source != "fastpath_sensitive" {
		t.Fatalf("expected sensitive ASK for config argument after git filename, got %+v", res)
	}
}

func TestFastPath_CustomXDGResolvedAccess(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/srv/xdg")
	filter := NewFilter(&mockBoundaryChecker{contained: true}, config.DefaultConfig())
	for _, call := range []harness.NormalizedToolCall{
		{ToolName: "Read", TargetPath: "git/config", Cwd: "/srv/xdg"},
		{ToolName: "Read", TargetPath: "config", Cwd: "/srv/xdg/git"},
		{ToolName: "Read", TargetPath: "/srv/xdg/git/../git/credentials"},
		{ToolName: "Bash", Command: "ls git/config", Cwd: "/srv/xdg"},
		{ToolName: "Bash", Command: "cat config", Cwd: "/srv/xdg/git"},
		{ToolName: "Bash", Command: `ls "git/../git/config"`, Cwd: "/srv/xdg"},
		{ToolName: "Read", TargetPath: "file:///srv/xdg/git/../git/config"},
	} {
		assertSensitiveAsk(t, filter, fmt.Sprintf("%+v", call), &call)
	}
	assertTrustedAllow(t, filter, "different cwd is not the XDG directory", &harness.NormalizedToolCall{ToolName: "Read", TargetPath: "git/config", Cwd: "/repo"})
	assertDeferred(t, filter, "resolved sensitive file with intent", &harness.NormalizedToolCall{ToolName: "Read", TargetPath: "config", Cwd: "/srv/xdg/git", UserIntent: "Read the Git config"})
}

func TestFastPath_CustomXDGWhitespaceDirectory(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/srv/xdg ")
	filter := NewFilter(&mockBoundaryChecker{contained: true}, config.DefaultConfig())
	assertSensitiveAsk(t, filter, "trailing space is part of directory", &harness.NormalizedToolCall{ToolName: "Read", TargetPath: "/srv/xdg /git/config"})
	assertSensitiveAsk(t, filter, "quoted relative whitespace directory", &harness.NormalizedToolCall{ToolName: "Bash", Command: `ls "xdg /git/config"`, Cwd: "/srv"})
}
