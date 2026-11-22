package fastpath

import (
	"os"
	"path/filepath"
	"testing"

	"jev-guard/pkg/harness"
)

// Bash and ripgrep read bracket expressions that Go's path.Match rejects or reads differently:
// POSIX classes, equivalence classes, collating symbols, a "]" first in the class and "!"
// negation. Each must single out a protected name just as "?" or "[g]" does.

func TestCheckAntiTampering_BracketClassCommands(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	ws := t.TempDir()
	for _, tc := range []struct {
		command string
		deny    bool
	}{
		{`cat ~/.jev?uard/state`, true},
		{`cat ~/.jev[g]uard/state`, true},
		{`cat ~/.jev[f-h]uard/state`, true},
		{`cat ~/.jev[[:alpha:]]uard/state`, true},
		{`cat ~/.jev[[:lower:]]uard/state`, true},
		{`cat ~/.jev[[:upper:]]uard/state`, true},
		{`cat ~/.jev[[:alnum:]]uard/state`, true},
		{`cat ~/.jev[[:word:]]uard/state`, true},
		{`cat ~/.jev[[:graph:]]uard/state`, true},
		{`cat ~/.jev[[=g=]]uard/state`, true},
		{`cat ~/.jev[[.g.]]uard/state`, true},
		{`cat ~/.jev[]fg]uard/state`, true},
		{`cat ~/.jev[!]x]uard/state`, true},
		{`cat ~/.jev[^]x]uard/state`, true},
		{`cat ~/.jev[^x]uard/state`, true},
		{`cat ~/.[[:alpha:]][[:alpha:]][[:alpha:]][[:alpha:]][[:alpha:]][[:alpha:]][[:alpha:]][[:alpha:]]/state`, false},
		{`cat ~/.jev[[:nosuchclass:]]uard/state`, true},
		{`cat ~/.jev[[.nosuchname.]]uard/state`, true},
		{`bash -c 'cat ~/.jev[[:alpha:]]uard/state'`, true},
		{`ls src/[a-c]*.go`, false},
		{`ls [[:upper:]]*.md`, false},
		{`ls src/[[:nosuchclass:]].go`, false},
		{`ls src/[]ab]*.go`, false},
		{`ls a[b`, false},
		{`[ -f x ] && echo y`, false},
	} {
		res := CheckAntiTampering(&harness.NormalizedToolCall{ToolName: "Bash", Command: tc.command, Cwd: ws})
		if tc.deny != IsTamperingDenial(res) || (!tc.deny && res != nil) {
			t.Errorf("CheckAntiTampering(%q) = %+v; want deny=%t", tc.command, res, tc.deny)
		}
	}
}

func TestCheckAntiTampering_BracketClassFileFilters(t *testing.T) {
	t.Setenv("JEV_GUARD_HOME", t.TempDir())
	grep := func(glob string) *harness.NormalizedToolCall {
		return &harness.NormalizedToolCall{ToolName: "Grep", TargetPath: ".", RawArgs: map[string]interface{}{"pattern": "x", "path": ".", "glob": glob}}
	}
	glob := func(pattern string) *harness.NormalizedToolCall {
		return &harness.NormalizedToolCall{ToolName: "Glob", RawArgs: map[string]interface{}{"pattern": pattern}}
	}
	for _, tc := range []struct {
		name string
		call *harness.NormalizedToolCall
		deny bool
	}{
		{"Grep ?", grep(".jev?uard.json"), true},
		{"Grep [f-h]", grep(".jev[f-h]uard.json"), true},
		{"Grep POSIX class", grep(".jev[[:alpha:]]uard.json"), true},
		{"Grep lower class", grep(".jev[[:lower:]]uard.json"), true},
		{"Grep equivalence class", grep(".jev[[=g=]]uard.json"), true},
		{"Grep ] first", grep(".jev[]fg]uard.json"), true},
		{"Grep ] first under **", grep("**/.jev[]fg]uard/**"), true},
		{"Grep ! negation", grep(".jev[!x]uard.json"), true},
		{"Grep ! negation with ]", grep(".jev[!]x]uard.json"), true},
		{"Grep ^ negation", grep(".jev[^x]uard.json"), true},
		{"Grep unknown class", grep(".jev[[:nosuchclass:]]uard.json"), true},
		{"Grep backslash in class (ripgrep literal)", grep(`.jev[f-h\]uard.json`), true},
		{"Grep backslash in class with ]", grep(`.jev[fg\]uard.json`), true},
		{"Grep backslash in negated class", grep(`.jev[!x\]uard.json`), true},
		{"Grep backslash after POSIX class", grep(`.jev[[:alpha:]\]uard.json`), true},
		{"Grep Windows separator", grep(`**\.jev[]fg]uard.json`), true},
		{"Glob ] first", glob(".jev[]fg]uard.json"), true},
		{"Glob POSIX class", glob("**/.jev[[:alpha:]]uard.json"), true},
		{"Grep unrelated class", grep("src/[a-c]*.go"), false},
		{"Grep unrelated POSIX class", grep("[[:upper:]]*.json"), false},
		{"Glob unrelated ] first", glob("src/[]ab]*.go"), false},
		{"Glob unrelated unknown class", glob("src/[[:nosuchclass:]].go"), false},
		{"Grep unrelated backslash in class", grep(`src/[a\]*.go`), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := CheckAntiTampering(tc.call)
			if tc.deny != IsTamperingDenial(res) || (!tc.deny && res != nil) {
				t.Fatalf("CheckAntiTampering = %+v; want deny=%t", res, tc.deny)
			}
		})
	}
}

func TestCheckAntiTampering_BracketClassCustomSecurityDirectory(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "secure-store")
	ws := filepath.Join(root, "ws")
	for _, dir := range []string{home, ws} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("JEV_GUARD_HOME", home)
	r := filepath.ToSlash(root)
	for _, tc := range []struct {
		command string
		deny    bool
	}{
		{"cat " + r + "/secure-st[o]re/state", true},
		{"cat " + r + "/secure-st[[:alpha:]]re/state", true},
		{"cat " + r + "/secure-st[[:lower:]]re/state", true},
		{"cat " + r + "/secure-st[[=o=]]re/state", true},
		{"cat " + r + "/secure-st[]o]re/state", true},
		{"cat " + r + "/secure-st[!]x]re/state", true},
		{"cat " + r + "/secure-st[[:nosuchclass:]]re/state", true},
		{"cat ../secure-st[[:alpha:]]re/state", true},
		{"cat " + r + "/[[:alpha:]]*/state", false},
		{"ls " + r + "/ws/[]ab]*.go", false},
	} {
		res := CheckAntiTampering(&harness.NormalizedToolCall{ToolName: "Bash", Command: tc.command, Cwd: ws})
		if tc.deny != IsTamperingDenial(res) || (!tc.deny && res != nil) {
			t.Errorf("CheckAntiTampering(%q) = %+v; want deny=%t", tc.command, res, tc.deny)
		}
	}
}

func TestGlobMatch(t *testing.T) {
	for _, tc := range []struct {
		pattern, name  string
		matched, exact bool
	}{
		{"[[:alpha:]]", "g", true, true},
		{"[[:alpha:]]", "1", false, true},
		{"[[:digit:]]", "1", true, true},
		{"[[:digit:]]", "g", false, true},
		{"[[:upper:]]", "g", true, true}, // names are compared lower-cased
		{"[[:space:]]", " ", true, true},
		{"[[:punct:]]", "-", true, true},
		{"[[:punct:]]", "g", false, true},
		{"[[:alpha:]]", "é", true, true},
		{"[[=g=]]", "g", true, true},
		{"[[.g.]]", "g", true, true},
		{"[]fg]", "]", true, true},
		{"[]fg]", "g", true, true},
		{"[]fg]", "h", false, true},
		{"[!]x]", "]", false, true},
		{"[!]x]", "g", true, true},
		{"[^]x]", "g", true, true},
		{"[!x]", "!", true, true},
		{"[!x]", "x", false, true},
		{"[a-]", "-", true, true},
		{"[-a]", "-", true, true},
		{"[[]", "[", true, true},
		{"a[b", "a[b", true, true},
		{"a[]", "a[]", true, true},
		{`a\`, `a\`, true, true},
		{`[\]]`, "]", true, false}, // Bash: a class holding "]"; ripgrep: a class holding "\", then "]"
		{"[[:nosuchclass:]]", "g", true, false},
		{"[[.nosuchname.]]", "g", true, false},
		{"x[[:nosuchclass:]]", "g", false, false},
		{"src/[a-c]*.go", "src/b.go", true, true},
		{`[f-h\]`, "g", true, false}, // ripgrep: a class with "\"; Bash: an unclosed "["
		{`[f-h\]`, `\`, true, false},
		{`[f-h\]`, "[f-h]", true, false},
		{`[f-h\]`, "x", false, false},
	} {
		matched, exact := globMatch(tc.pattern, tc.name)
		if matched != tc.matched || exact != tc.exact {
			t.Errorf("globMatch(%q, %q) = %t, %t; want %t, %t", tc.pattern, tc.name, matched, exact, tc.matched, tc.exact)
		}
	}
}

// The hook-config write check reads bracket expressions the same way, including an
// equivalence class whose "=" is not an option's "--name=value".
func TestHookConfigBracketClasses(t *testing.T) {
	home, ws := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for _, command := range []string{
		"sed -i s/a/b/ .claude/settin?s.json",
		"sed -i s/a/b/ .claude/settin[g]s.json",
		"sed -i s/a/b/ .claude/settin[[:alpha:]]s.json",
		"sed -i s/a/b/ .claude/settin[]g]s.json",
		"sed -i s/a/b/ .claude/settin[!x]s.json",
		"sed -i s/a/b/ .claude/settin[[:nosuchclass:]]s.json",
		"rm .codex/hook[[=s=]].json",
		"rm .claude/settin[[=g=]]s.json",
		"rm ~/.codex/hook[[.s.]].json",
		"rm .cod[[:alpha:]]x/hooks.json",
		`rm .claude/settin[f-h\]s.json`,
		"cp x --target-file=.claude/settings.json",
	} {
		assertHookConfigAsk(t, &harness.NormalizedToolCall{ToolName: "Bash", Command: command, Cwd: ws})
	}
	for _, command := range []string{
		"rm src/[[:alpha:]]*.go",
		"rm src/[]ab]*.go",
		"sed -i s/a/b/ src/a=b.txt",
		"rm build/[[:nosuchclass:]].o",
	} {
		if result := CheckAntiTampering(&harness.NormalizedToolCall{ToolName: "Bash", Command: command, Cwd: ws}); result != nil {
			t.Errorf("CheckAntiTampering(%q) = %+v; want nil", command, result)
		}
	}
}
