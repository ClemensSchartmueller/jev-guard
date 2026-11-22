package fastpath

import (
	"jev-guard/pkg/harness"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHookReviewNoVerdicts(t *testing.T) {
	commands := []string{
		"git add *", "du -sh *", "tar czf /tmp/a.tgz *", "zip -r a.zip *", "touch *", "chmod +x *", "prettier --write *", "for f in *; do echo $f; done", "echo $((3 * 4))", "shopt -s dotglob; echo $((3 * 4))", `shopt -s dotglob; echo "$((3 * 4))"`, "shopt -s dotglob; ((3 * 4))", "((3 * 4))", "expr 3 \\* 4",
		"cat > a.py <<'EOF'\narea = width * height\nEOF",
		"sqlite3 app.db <<'EOF'\nSELECT * FROM users;\nEOF",
		"cat > notes.md <<'EOF'\n- see * below\nEOF",
		"git commit -F - <<'EOF'\nUpdate .claude/settings.json handling.\nEOF",
		"cat > README.md <<'EOF'\nAdd the hook to .claude/settings.json\nEOF",
		"cat > src/gen.ts <<'EOF'\n" + strings.Repeat("const x = width * height;\n", 4500) + "EOF",
		"find .claude -name '*.md'", "tree .claude", "du -sh .claude", "git ls-files .claude", "node build.js .claude", "git unknown .claude", "xcopy .claude backup",
		"md5sum .claude/settings.json", "sha256sum .claude/settings.json", "bat .claude/settings.json", "python3 -m json.tool .claude/settings.json", "code .claude/settings.json", "git add .claude/settings.json", "git rm --cached .claude/settings.json",
		"mkdir -p src/{components,hooks,utils,pages,styles,lib,api,types}/{__tests__,fixtures,mocks}",
		"rm -f build/*.o dist/*.js cache/*.tmp", "find src -name '*.go' | xargs gofmt -w",
		"cat > main.go <<'EOF'\n" + strings.Repeat("// ordinary source\n", 6000) + "EOF",
	}
	cwd := t.TempDir()
	for i := 0; i < 10; i++ {
		cwd = filepath.Join(cwd, "longdirname")
	}
	if err := os.MkdirAll(cwd, 0700); err != nil {
		t.Fatal(err)
	}
	for _, command := range commands {
		start := time.Now()
		got := CheckAntiTampering(&harness.NormalizedToolCall{ToolName: "Bash", Command: command, Cwd: cwd})
		if got != nil {
			t.Errorf("%.120s: want no verdict, got %+v", command, got)
		}
		if time.Since(start) > 2*time.Second {
			t.Errorf("%.120s: too slow", command)
		}
	}
	if got := checkHookConfigChanges(&harness.NormalizedToolCall{ToolName: "WebFetch", TargetPath: ".claude/settings.json", Cwd: cwd}); got != nil {
		t.Fatal(got)
	}
}

func TestHookReviewWrites(t *testing.T) {
	cwd := t.TempDir()
	assertHookConfigAsk(t, &harness.NormalizedToolCall{ToolName: "PowerShell", Command: "Remove-Item *", Cwd: cwd})
	assertHookConfigAsk(t, &harness.NormalizedToolCall{ToolName: "PowerShell", Command: `Set-Content .claude\settings.json x`, Cwd: cwd})
	commands := []string{
		`Set-Content .claude\settings.json x`,
		`cmd /c "del .claude\settings.json"`,
		`pwsh -c "Set-Content .claude\settings.json x"`,
		`del .claude\settings.json`, `copy x .claude\settings.json`, `move .claude\settings.json x`, `erase .claude\settings.json`, `ren .claude\settings.json x`, `xcopy x .claude\settings.json`,
		"cd .claude 2>/dev/null && echo x > settings.json", "cd 2>/dev/null .claude; echo x > settings.json",
		"cd .claude > /dev/null; echo x > settings.json",
		"pushd .claude >/dev/null; rm settings.json",
		"cd .claude; cd zz; echo x > settings.json",
		"cd .claude; cd /tmp | true; echo x > settings.json",
		"cd .claude; cd /tmp; cd -; echo x > settings.json",
		"pushd .claude; pushd /tmp; popd; rm settings.json",
		"echo x >| .claude/settings.json", "cd .claude && echo x >| settings.json",
		"echo x >& .claude/settings.json", "echo x &> .claude/settings.json", "echo x &>> .claude/settings.json",
		`python3 -c "open('.claude/settings.json','w').write('{}')"`,
		`node -e "require('fs').writeFileSync('.claude/settings.json','{}')"`,
		`perl -e "open(F, '>.claude/settings.json')"`,
		`ruby -e "File.write('.claude/settings.json','{}')"`,
		`php -r "file_put_contents('.claude/settings.json','{}')"`,
		`php -e "file_put_contents('.claude/settings.json','{}')"`,
		`deno --eval "Deno.writeTextFileSync('.claude/settings.json','{}')"`,
		"dd of=.claude/settings.json if=/tmp/x", "tool --file=.claude/settings.json",
		"bash <<'EOF'\nrm .claude/settings.json\nEOF",
		"sh -s <<'EOF'\nrm .claude/settings.json\nEOF",
		"cat <<'EOF' | sh\nrm .claude/settings.json\nEOF",
		"cat > x <<EOF\n$(rm .claude/settings.json)\nEOF", "cat > x <<EOF\n'$(rm .claude/settings.json)'\nEOF",
		"cat > x <<EOF\n`rm .claude/settings.json`\nEOF",
		"shopt -s dotglob; rm *", "GLOBIGNORE=x; rm *",
		`echo "$(( $(rm .claude/settings.json) + 1 ))"`,
	}
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			assertHookConfigAsk(t, &harness.NormalizedToolCall{ToolName: "Bash", Command: command, Cwd: cwd})
		})
	}
	for _, words := range [][]interface{}{
		{"powershell.exe", "-Command", `Remove-Item .claude\settings.json`},
		{"powershell.exe", "-NoProfile", "-Command", `Set-Content -Path .claude\settings.json -Value x`},
		{"cmd.exe", "/c", `del .claude\settings.json`},
	} {
		assertHookConfigAsk(t, &harness.NormalizedToolCall{ToolName: "exec_command", RawArgs: map[string]interface{}{"cmd": words}, Cwd: cwd})
	}
}

func TestHookReviewNavigationLimit(t *testing.T) {
	// Distinct binary alternatives switch to unknown cwd without blocking ordinary work.
	command := ""
	for i := 0; i < 6; i++ {
		command += "cd dir" + strings.Repeat("x", i) + "; "
	}
	got := CheckAntiTampering(&harness.NormalizedToolCall{ToolName: "Bash", Command: command + "echo ordinary", Cwd: t.TempDir()})
	if got != nil {
		t.Fatalf("want no verdict for unrelated work after cwd saturation, got %+v", got)
	}
}
