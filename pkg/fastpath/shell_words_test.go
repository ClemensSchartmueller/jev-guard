package fastpath

import (
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"testing"

	"jev-guard/pkg/harness"
)

func TestShellWordReaders(t *testing.T) {
	for _, tc := range []struct {
		name  string
		read  func(string) []string
		input string
		want  []string
	}{
		{"posix backslash", posixWords, `cat d\ata`, []string{"cat", "data"}},
		{"posix escaped space", posixWords, `a\ b c`, []string{"a b", "c"}},
		{"posix continuation", posixWords, "d\\\nata", []string{"data"}},
		{"posix trailing backslash", posixWords, `a\`, []string{"a"}},
		{"posix adjacent", posixWords, `d"a"t'a'`, []string{"data"}},
		{"posix empty word", posixWords, `a ""`, []string{"a", ""}},
		{"posix double keeps backslash", posixWords, `"d\ata"`, []string{`d\ata`}},
		{"posix double escapes", posixWords, `"a\"b\\c\$d"`, []string{`a"b\c$d`}},
		{"posix single is literal", posixWords, `'a\b"c'`, []string{`a\b"c`}},
		{"posix unterminated single", posixWords, `'abc`, []string{"abc"}},
		{"posix unterminated double", posixWords, `"abc`, []string{"abc"}},
		{"ansi hex", posixWords, `$'d\x61ta'`, []string{"data"}},
		{"ansi octal", posixWords, `$'d\141ta'`, []string{"data"}},
		{"ansi unicode", posixWords, `$'\u0064\U00000061'`, []string{"da"}},
		{"ansi control", posixWords, `$'\ca'`, []string{"\x01"}},
		{"ansi escaped quote", posixWords, `$'a\'b' c`, []string{"a'b", "c"}},
		{"ansi unterminated", posixWords, `$'ab`, []string{"ab"}},
		{"ansi bad hex", posixWords, `$'\xZ'`, []string{`\xZ`}},
		{"locale", posixWords, `$"da"ta`, []string{"data"}},
		{"powershell backtick", powerShellWords, "d`a`t`a", []string{"data"}},
		{"powershell space", powerShellWords, "a` b c", []string{"a b", "c"}},
		{"powershell keeps backslash", powerShellWords, `C:\x\y`, []string{`C:\x\y`}},
		{"powershell single", powerShellWords, "'a`b''c'", []string{"a`b'c"}},
		{"powershell double", powerShellWords, "\"a`\"b\"\"c\"", []string{`a"b"c`}},
		{"cmd caret", cmdWords, "d^a^t^a x", []string{"data", "x"}},
		{"cmd keeps backslash", cmdWords, `C:\x\y`, []string{`C:\x\y`}},
		{"cmd quotes", cmdWords, `"a ^b" c`, []string{"a ^b", "c"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.read(tc.input); !slices.Equal(got, tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// Each shell's reading is kept: applying one shell's rules must not lose another's spelling.
func TestShellWordsKeepEveryReading(t *testing.T) {
	words := shellWords(`type C:\Users\d^ata x\y`)
	for _, want := range []string{`C:\Users\d^ata`, `C:\Users\data`, "C:Usersd^ata", "x\\y", "xy"} {
		if !slices.Contains(words, want) {
			t.Errorf("missing %q in %q", want, words)
		}
	}
}

func TestShellWordFormsAndNesting(t *testing.T) {
	for input, want := range map[string]string{
		`--file=d\ata`:                 "data",
		`-od\ata`:                      "data",
		`@d\ata`:                       "data",
		`a,d\ata`:                      "data",
		`x>>d\ata`:                     "data",
		`sh -c 'cat d\ata'`:            "data",
		`bash -c "sh -c 'cat d\\ata'"`: "data",
		`$(cat d\ata)`:                 "data",
	} {
		if words := shellWords(input); !slices.Contains(words, want) {
			t.Errorf("%q: missing %q in %q", input, want, words)
		}
	}
}

// Nesting and repetition must not blow up on hostile input.
func TestShellWordsStayBounded(t *testing.T) {
	deep := "x"
	for range 50 {
		deep = `sh -c "` + strings.ReplaceAll(deep, `"`, `\"`) + `"`
		if len(deep) > 1<<16 {
			break
		}
	}
	if words := shellWords(deep); len(words) == 0 {
		t.Fatal("no words")
	}
}

// A path after an operator survives whole, including a drive letter's colon.
func TestWordFormsKeepDrivePaths(t *testing.T) {
	for input, wants := range map[string][]string{
		"x>>C:/a/b":     {"C:/a/b"},
		"--file=C:/a/b": {"C:/a/b"},
		"PATH=/a:/b":    {"/a:/b", "/a", "/b"},
		"-oC:/a/b":      {"C:/a/b"},
		"host:/a/b":     {"/a/b"},
	} {
		forms := wordForms(input)
		for _, want := range wants {
			if !slices.Contains(forms, want) {
				t.Errorf("%q: missing %q in %q", input, want, forms)
			}
		}
	}
}

func TestWindowsDriveFromMSYS(t *testing.T) {
	for input, want := range map[string]string{
		"/c/Users/x/data": "c:/Users/x/data",
		"/D":              "D:",
		"/d/":             "d:/",
		"/usr/bin":        "",
		"c/Users":         "",
		"":                "",
	} {
		if got := windowsDriveFromMSYS(input); got != want {
			t.Errorf("%q: got %q, want %q", input, got, want)
		}
	}
}

func BenchmarkTranscriptGuardTypicalCommand(b *testing.B) {
	call := &harness.NormalizedToolCall{Command: `git log --oneline -5 && go test ./pkg/... 2>&1 | tail -20`, Cwd: b.TempDir()}
	for range b.N {
		CheckTranscriptTampering(call)
	}
}

func BenchmarkTranscriptGuardLargeCommand(b *testing.B) {
	var sb strings.Builder
	sb.WriteString("cat > out.txt <<'EOF'\n")
	for i := 0; sb.Len() < 1<<20; i++ {
		sb.WriteString("some/path/word" + strings.Repeat("x", i%7) + " ")
	}
	call := &harness.NormalizedToolCall{Command: sb.String(), Cwd: b.TempDir()}
	for range b.N {
		CheckTranscriptTampering(call)
	}
}

// Bash truncates an ANSI-C quoted segment at the first decoded NUL and reads on.
func TestANSICNulTruncation(t *testing.T) {
	cases := map[string]string{
		`a$'\0'b`:          "ab",
		`a$'\x00ignored'b`: "ab",
		`a$'\u0000x'b`:     "ab",
		`a$'x\000y\'z'b`:   "axb",
		`a$'\c@x'b`:        "ab",
		`a$'\x61\x00'b`:    "aab",
	}
	for input, want := range cases {
		if got := posixWords(input); !slices.Equal(got, []string{want}) {
			t.Errorf("posixWords(%q) = %q; want [%q]", input, got, want)
		}
	}
	bash, err := exec.LookPath("bash")
	if err != nil || runtime.GOOS == "windows" {
		t.Skip("bash not available for the differential check")
	}
	// Bash before 4.2 (macOS ships 3.2) has no \u escape and keeps it literally. The reader
	// follows newer Bash, which only adds denials, so skip those cases on an old bash.
	probe, _ := exec.Command(bash, "--norc", "--noprofile", "-c", `printf '%s' $'\u0041'`).Output()
	hasUnicodeEscapes := string(probe) == "A"
	for input, want := range cases {
		if strings.Contains(input, `\u`) && !hasUnicodeEscapes {
			continue
		}
		out, err := exec.Command(bash, "--norc", "--noprofile", "-c", "printf '%s' "+input).Output()
		if err != nil {
			t.Fatalf("bash %q: %v", input, err)
		}
		if string(out) != want {
			t.Errorf("bash reads %q as %q; the reader expects %q", input, out, want)
		}
	}
}

func TestShellReaderPatterns(t *testing.T) {
	for input, want := range map[string][]string{
		`cat ~/.jev*/x`:         {"~/.jev*/x"},
		`cat ~/.{jev,x}guard`:   {"~/.{jev,x}guard"},
		`cat '*' "a*"`:          nil,
		`cat a"*"*`:             {`a\**`},
		`ls *.go`:               {"*.go"},
		`echo x`:                nil,
		`Get-Content a*`:        {"a*"},
		"Get-Content 'a*'":      nil,
		`find . -name '*.json'`: nil,
	} {
		_, patterns := newShellReader().read(input, false)
		if !slices.Equal(patterns, want) {
			t.Errorf("%q: patterns %q; want %q", input, patterns, want)
		}
	}
}
