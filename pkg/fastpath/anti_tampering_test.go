package fastpath

import (
	"fmt"
	"strings"
	"testing"

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
