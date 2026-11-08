package fastpath

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"jev-guard/pkg/harness"
)

func TestCheckAntiTampering_ShellEscapes(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	for _, tc := range []struct {
		name    string
		command string
		deny    bool
	}{
		{"plain", `cat ~/.jevguard/state`, true},
		{"backslash escape", `cat ~/.jev\guard/state`, true},
		{"adjacent double quotes", `cat ~/.jev"guard"/state`, true},
		{"adjacent single quotes", `cat ~/.jev'guard'/state`, true},
		{"empty quotes", `cat ~/.jev""guard/state`, true},
		{"ANSI-C quoting", `cat ~/.jev$'guard'/state`, true},
		{"ANSI-C hex escape", `cat ~/.jev$'\x67'uard/state`, true},
		{"locale quoting", `cat ~/.jev$"guard"/state`, true},
		{"upper case", `cat ~/.JEV\GUARD/state`, true},
		{"config file name escaped", `echo x > jev\guard.json`, true},
		{"PowerShell backtick", "Get-Content ~/.jev`guard/state", true},
		{"cmd caret", `type %USERPROFILE%\.jev^guard\state`, true},
		{"nested sh -c", `bash -c 'cat ~/.jev\guard/state'`, true},
		{"command substitution", `echo $(cat ~/.jev\guard/state)`, true},
		{"redirect target", `echo '{}'>~/.jev"guard"/x`, true},
		{"word mentioning name", `grep -rn jevguard README.md`, false},
		{"go identifier", `grep -rn GetJevguardDir .`, false},
		{"project name", `cat .jev-guard`, false},
		{"plain listing", `ls -la`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := CheckAntiTampering(&harness.NormalizedToolCall{ToolName: "Bash", Command: tc.command})
			if tc.deny != IsTamperingDenial(res) || (!tc.deny && res != nil) {
				t.Fatalf("CheckAntiTampering(%q) = %+v; want deny=%t", tc.command, res, tc.deny)
			}
		})
	}
}

func TestCheckAntiTampering_CommandArguments(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	for name, raw := range map[string]interface{}{
		"string":           `cat ~/.jev\guard/state`,
		"list payload":     []interface{}{"bash", "-lc", `cat ~/.jev\guard/state`},
		"list plain word":  []interface{}{"cat", "/home/u/.jevguard/state"},
		"CommandLine list": []string{"pwsh", "-Command", "Get-Content ~/.jev`guard/state"},
	} {
		t.Run(name, func(t *testing.T) {
			call := &harness.NormalizedToolCall{ToolName: "exec", RawArgs: map[string]interface{}{"command": raw}}
			if _, ok := raw.([]string); ok {
				call.RawArgs = map[string]interface{}{"CommandLine": raw}
			}
			if res := CheckAntiTampering(call); !IsTamperingDenial(res) {
				t.Fatalf("CheckAntiTampering = %+v; want DENY", res)
			}
		})
	}
}

func TestCheckAntiTampering_Limits(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	huge := "echo " + strings.Repeat("a", maxGuardCommandBytes)
	res := CheckAntiTampering(&harness.NormalizedToolCall{ToolName: "Bash", Command: huge})
	if res == nil || res.Decision != harness.DecisionAsk || res.Source != SourceAntiTamperingLimit || IsTamperingDenial(res) {
		t.Fatalf("oversized command = %+v; want ASK %s", res, SourceAntiTamperingLimit)
	}

	// The raw text check still runs on a command too large to read word by word.
	res = CheckAntiTampering(&harness.NormalizedToolCall{ToolName: "Bash", Command: huge + " ~/.jevguard/state"})
	if !IsTamperingDenial(res) {
		t.Fatalf("oversized command naming ~/.jevguard = %+v; want DENY", res)
	}

	var b strings.Builder
	b.WriteString("echo")
	for i := 0; i <= maxGuardWords; i++ {
		fmt.Fprintf(&b, " w%d", i)
	}
	res = CheckAntiTampering(&harness.NormalizedToolCall{ToolName: "Bash", Command: b.String()})
	if res == nil || res.Decision != harness.DecisionAsk || res.Source != SourceAntiTamperingLimit {
		t.Fatalf("command with too many words = %+v; want ASK %s", res, SourceAntiTamperingLimit)
	}

	list := []interface{}{"echo", strings.Repeat("a", maxGuardCommandBytes+1)}
	res = CheckAntiTampering(&harness.NormalizedToolCall{ToolName: "exec", RawArgs: map[string]interface{}{"command": list}})
	if res == nil || res.Decision != harness.DecisionAsk || res.Source != SourceAntiTamperingLimit {
		t.Fatalf("oversized argument list = %+v; want ASK %s", res, SourceAntiTamperingLimit)
	}
}

func TestPatternTargetsJevguard(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		want    bool
	}{
		{".jevguard.json", true},
		{"*jevguard*.json", true},
		{"*JevGuard*", true},
		{"**/*jevguard*", true},
		{`\.jevguard.json`, true},
		{"*jev[g]uard*", true},
		{"*jev?uard*", true},
		{".jev*", true},
		{"**/.jev*guard*", true},
		{"*uard.log", true},
		{".{jev,x}guard.json", true},
		{`**\.jev*`, true},
		{"*", false},
		{"**/*", false},
		{"*.json", false},
		{".*", false},
		{"*.log", false},
		{"**/*.{json,md}", false},
		{"src/**/*.go", false},
		{".jev-guard*", false},
		{"*.json.example", false},
	} {
		if got := patternTargetsJevguard(tc.pattern); got != tc.want {
			t.Errorf("patternTargetsJevguard(%q) = %t; want %t", tc.pattern, got, tc.want)
		}
	}
	if !patternTargetsJevguard(strings.Repeat("{a,b}", 7)) {
		t.Error("a pattern with more alternatives than the limit must be denied")
	}
	if !patternTargetsJevguard(strings.Repeat("a", maxPathLikeBytes+1)) {
		t.Error("an oversized pattern must be denied")
	}
}

func TestCheckAntiTampering_WildcardFileFilters(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	for _, tc := range []struct {
		name string
		call *harness.NormalizedToolCall
		deny bool
	}{
		{"Grep wildcard glob", &harness.NormalizedToolCall{ToolName: "Grep", TargetPath: ".", RawArgs: map[string]interface{}{"pattern": "api_key", "path": ".", "glob": "*jevguard*.json"}}, true},
		{"Glob partial name", &harness.NormalizedToolCall{ToolName: "Glob", RawArgs: map[string]interface{}{"pattern": "**/.jev*"}}, true},
		{"find_by_name wildcard", &harness.NormalizedToolCall{ToolName: "find_by_name", TargetPath: "/ws", RawArgs: map[string]interface{}{"SearchDirectory": "/ws", "Pattern": "*jevguard*"}}, true},
		{"grep_search Includes wildcard", &harness.NormalizedToolCall{ToolName: "grep_search", TargetPath: "/ws", RawArgs: map[string]interface{}{"SearchPath": "/ws", "Query": "key", "Includes": []interface{}{"*.go", "*JEVGUARD*"}}}, true},
		{"Grep broad glob", &harness.NormalizedToolCall{ToolName: "Grep", TargetPath: ".", RawArgs: map[string]interface{}{"pattern": "api_key", "path": ".", "glob": "*.json"}}, false},
		{"Glob everything", &harness.NormalizedToolCall{ToolName: "Glob", RawArgs: map[string]interface{}{"pattern": "**/*"}}, false},
		{"Grep content pattern only", &harness.NormalizedToolCall{ToolName: "Grep", TargetPath: ".", RawArgs: map[string]interface{}{"pattern": "*jevguard*", "path": ".", "glob": "*.go"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := CheckAntiTampering(tc.call)
			if tc.deny != IsTamperingDenial(res) || (!tc.deny && res != nil) {
				t.Fatalf("CheckAntiTampering = %+v; want deny=%t", res, tc.deny)
			}
		})
	}
}

// Bash drops the rest of an ANSI-C quoted segment after a decoded NUL, then reads on.
func TestCheckAntiTampering_ANSICNul(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	for _, command := range []string{
		`cat ~/.jev$'\0'guard/state`,
		`cat ~/.jev$'\x00ignored'guard/state`,
		`cat ~/.jev$'\u0000'guard/state`,
		`cat ~/.jev$'\U00000000x'guard/state`,
		`cat ~/.jev$'\c@x'guard/state`,
		`cat ~/.jev$'\000\'x'guard/state`,
	} {
		if res := CheckAntiTampering(&harness.NormalizedToolCall{ToolName: "Bash", Command: command}); !IsTamperingDenial(res) {
			t.Errorf("CheckAntiTampering(%q) = %+v; want DENY", command, res)
		}
	}
}

// Shell glob and brace patterns that single out a protected name are denied; quoted
// metacharacters are literal, and broad or ordinary patterns pass.
func TestCheckAntiTampering_ShellPatterns(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	ws := t.TempDir()
	for _, tc := range []struct {
		command string
		deny    bool
	}{
		{`cat ~/.jev*/state`, true},
		{`cat ~/.{jev,x}guard/state`, true},
		{`cat ~/.jev?uard/state`, true},
		{`cat ~/.jev[!x]uard/state`, true},
		{`cat ~/.jev{g..g}uard/state`, true},
		{`cat ~/.jev{f..h}uard/state`, true},
		{`cat $HOME/.jev*/state`, true},
		{`echo x>~/.jev*/state`, true},
		{`ls ~/.j*`, true},
		{`cat ~/.jev"g"*/state`, true},
		{`bash -c 'cat ~/.jev*/state'`, true},
		{"Get-Content ~/.jev*/state", true},
		{`cat '~/.jev*/state'`, false},
		{`cat ~/.jev\*/state`, false},
		{`find . -name '*.json'`, false},
		{`ls *.go`, false},
		{`rm -rf build/*`, false},
		{`git add .`, false},
		{`ls -a .*`, false},
		{`cp *.json /tmp/out/`, false},
		{`echo {a,b}.txt`, false},
		{`for i in {1..1000}; do echo $i; done`, false},
		{`ls src/**/*.{go,md}`, false},
		{`[[ -f x ]] && echo y`, false},
		{`grep -rn 'jev.*guard' .`, false},
	} {
		res := CheckAntiTampering(&harness.NormalizedToolCall{ToolName: "Bash", Command: tc.command, Cwd: ws})
		if tc.deny != IsTamperingDenial(res) || (!tc.deny && res != nil) {
			t.Errorf("CheckAntiTampering(%q) = %+v; want deny=%t", tc.command, res, tc.deny)
		}
	}
}

func TestExpandBraceSequences(t *testing.T) {
	for in, want := range map[string]string{
		"a{g..g}b":   "agb",
		"{f..h}":     "{f,g,h}",
		"{h..f}":     "{f,g,h}",
		"{1..1000}":  "1",
		"{a..e..2}":  "{a,b,c,d,e}",
		"{Z..a}":     `{Z,\[,\\,\],\^,_,` + "`" + `,a}`,
		"{a,b}":      "{a,b}",
		"{1..x}":     "{1..x}",
		"plain text": "plain text",
	} {
		if got := expandBraceSequences(in); got != want {
			t.Errorf("expandBraceSequences(%q) = %q; want %q", in, got, want)
		}
	}
}

// A command whose words reach a custom security directory is denied, whatever its spelling.
func TestCheckAntiTampering_CustomSecurityDirectory(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "jevguard-home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JEV_GUARD_HOME", home)
	ws := filepath.Join(root, "ws")
	if err := os.MkdirAll(ws, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "innocent")
	symlinked := os.Symlink(home, link) == nil
	for _, tc := range []struct {
		name string
		call *harness.NormalizedToolCall
		deny bool
	}{
		{"absolute", &harness.NormalizedToolCall{ToolName: "Bash", Command: "cat " + filepath.Join(home, "state"), Cwd: ws}, true},
		{"quoted", &harness.NormalizedToolCall{ToolName: "Bash", Command: `cat "` + home + `/state"`, Cwd: ws}, true},
		{"directory itself", &harness.NormalizedToolCall{ToolName: "Bash", Command: "rm -rf " + home, Cwd: ws}, true},
		{"variable", &harness.NormalizedToolCall{ToolName: "Bash", Command: `cat "$JEV_GUARD_HOME/state"`, Cwd: ws}, true},
		{"relative", &harness.NormalizedToolCall{ToolName: "Bash", Command: "cat ../jevguard-home/state", Cwd: ws}, true},
		{"redirect", &harness.NormalizedToolCall{ToolName: "Bash", Command: "echo {} >" + filepath.Join(home, "config.json"), Cwd: ws}, true},
		{"nested", &harness.NormalizedToolCall{ToolName: "Bash", Command: `bash -c "cat ` + home + `/state"`, Cwd: ws}, true},
		{"argument list", &harness.NormalizedToolCall{ToolName: "exec", Cwd: ws, RawArgs: map[string]interface{}{"command": []interface{}{"cat", filepath.Join(home, "state")}}}, true},
		{"sibling", &harness.NormalizedToolCall{ToolName: "Bash", Command: "cat " + filepath.Join(root, "jevguard-home2", "state"), Cwd: ws}, false},
		{"workspace file", &harness.NormalizedToolCall{ToolName: "Bash", Command: "cat ./src/main.go ../ws/README.md", Cwd: ws}, false},
	} {
		res := CheckAntiTampering(tc.call)
		if tc.deny != IsTamperingDenial(res) || (!tc.deny && res != nil) {
			t.Errorf("%s: CheckAntiTampering = %+v; want deny=%t", tc.name, res, tc.deny)
		}
	}
	if symlinked {
		if res := CheckAntiTampering(&harness.NormalizedToolCall{ToolName: "Bash", Command: "cat " + link + "/state", Cwd: ws}); !IsTamperingDenial(res) {
			t.Errorf("symlink to the security directory: %+v; want DENY", res)
		}
	}
}

func TestCheckAntiTampering_ApplyPatchHeaders(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "jevguard-home")
	t.Setenv("JEV_GUARD_HOME", home)
	ws := filepath.Join(root, "ws")
	patch := func(header string) string {
		return "*** Begin Patch\n" + header + "\n@@\n-a\n+b\n*** End Patch\n"
	}
	for _, tc := range []struct {
		name   string
		header string
		deny   bool
	}{
		{"delete", "*** Delete File: " + filepath.Join(home, "state"), true},
		{"add", "*** Add File: " + filepath.Join(home, "config.json"), true},
		{"update", "*** Update File: " + filepath.Join(home, "trust.json"), true},
		{"move to", "*** Update File: notes.txt\n*** Move to: " + filepath.Join(home, "state"), true},
		{"relative", "*** Delete File: ../jevguard-home/state", true},
		{"default directory", "*** Delete File: ~/.jevguard/state", true},
		{"crlf", "*** Delete File: " + filepath.Join(home, "state") + "\r", true},
		{"workspace file", "*** Update File: src/main.go", false},
	} {
		for _, key := range []string{"input", "patch"} {
			call := &harness.NormalizedToolCall{ToolName: "apply_patch", Cwd: ws, RawArgs: map[string]interface{}{key: patch(tc.header)}}
			res := CheckAntiTampering(call)
			if tc.deny != IsTamperingDenial(res) || (!tc.deny && res != nil) {
				t.Errorf("%s (%s): CheckAntiTampering = %+v; want deny=%t", tc.name, key, res, tc.deny)
			}
		}
	}
	// A patch passed as a shell command is checked the same way.
	shell := &harness.NormalizedToolCall{ToolName: "Bash", Cwd: ws, Command: "apply_patch <<'EOF'\n" + patch("*** Delete File: ../jevguard-home/state") + "EOF"}
	if res := CheckAntiTampering(shell); !IsTamperingDenial(res) {
		t.Errorf("shell apply_patch: %+v; want DENY", res)
	}
}

// Reading a command is bounded by a cumulative work budget, checked before text is copied or
// read again, so hostile nesting stops quickly with the limit ASK instead of running for minutes.
func TestCheckAntiTampering_WorkIsBounded(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	nestedShells := "x"
	for range 12 {
		nestedShells = `bash -c "` + strings.ReplaceAll(strings.ReplaceAll(nestedShells, `\`, `\\`), `"`, `\"`) + `"`
	}
	for _, tc := range []struct {
		name    string
		command string
		limit   bool // the limit ASK is required, not just allowed
	}{
		{"eval repeat", strings.Repeat("eval ", 2000), true},
		{"eval repeat long", strings.Repeat("eval ", 200_000), true},
		{"bash -c repeat", strings.Repeat("bash -c bash -c ", 20_000), true},
		{"shell scan repeat", strings.Repeat("sh ", 300_000), true},
		{"interpreter scan repeat", strings.Repeat("python ", 200_000), true},
		{"cmd repeat", strings.Repeat("cmd /c ", 100_000), true},
		{"powershell repeat", strings.Repeat("pwsh ", 100_000), true},
		{"nested bash -c", nestedShells, false},
		{"wide bash -c", strings.Repeat(`bash -c "eval eval eval x"; `, 5000), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			res := CheckAntiTampering(&harness.NormalizedToolCall{ToolName: "Bash", Command: tc.command})
			if elapsed := time.Since(start); elapsed > 3*time.Second {
				t.Errorf("took %v", elapsed)
			}
			if IsTamperingDenial(res) || (res != nil && res.Source != SourceAntiTamperingLimit) || (tc.limit && res == nil) {
				t.Errorf("result = %+v; want the limit ASK (required=%t)", res, tc.limit)
			}

			// The transcript guard shares the reader, and keeps its own limit source.
			start = time.Now()
			res = CheckTranscriptTampering(&harness.NormalizedToolCall{ToolName: "Bash", Command: tc.command})
			if elapsed := time.Since(start); elapsed > 3*time.Second {
				t.Errorf("transcript guard took %v", elapsed)
			}
			if (res != nil && res.Source != sourceTranscriptGuardLimit) || (tc.limit && res == nil) {
				t.Errorf("transcript guard result = %+v; want %s (required=%t)", res, sourceTranscriptGuardLimit, tc.limit)
			}
		})
	}

	// The budget is charged before work happens: a reader never goes far past it.
	r := newShellReader()
	r.read(strings.Repeat("eval ", 2000), false)
	if !r.exhausted || r.bytes > maxShellReadBytes+maxGuardCommandBytes || r.payloads > maxShellPayloads+1 {
		t.Errorf("reader work bytes=%d payloads=%d exhausted=%t; want stopped at the budget", r.bytes, r.payloads, r.exhausted)
	}

	// Ordinary nesting stays readable and is still checked.
	for _, command := range []string{`eval "cat ~/.jev\guard/state"`, `eval eval 'cat ~/.jev\guard/state'`, `bash -c "sh -c 'cat ~/.jev\\guard/state'"`} {
		if res := CheckAntiTampering(&harness.NormalizedToolCall{ToolName: "Bash", Command: command}); !IsTamperingDenial(res) {
			t.Errorf("CheckAntiTampering(%q) = %+v; want DENY", command, res)
		}
	}
}
