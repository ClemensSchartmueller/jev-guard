package fastpath

import (
	"jev-guard/pkg/harness"
	"strings"
	"testing"
)

func TestHookRoundFourWrites(t *testing.T) {
	cwd := t.TempDir()
	t.Setenv("HOME", cwd)
	commands := []string{
		`rm -rf ~/.claude/*`, `rm -rf ~/.codex/*`, `rm -f ./.claude/*`, `rm ./.claude/*.json`, `rm ~/.claude/settings*`, `rm ../.claude/*.json`, `rm -rf ./.codex/*`, `rm -rf ./.*`, `rm -rf ~/.c*`, `cp x ./.claude/settings.js*`,
		`rm $HOME/.claude/settings*`, `rm ${HOME}/.claude/settings*`,
		`(rm .claude/settings.json)`, `(echo x > .claude/settings.json)`, `(cd /tmp && rm -rf ~/.claude)`, `test -f x && (rm -f .claude/settings.local.json)`, `(cd .claude && rm settings.json)`, `(cd .codex; rm hooks.json)`, `{ cd .claude; rm settings.json; }`, `if cd .claude; then rm settings.json; fi`,
		"python3 - <<'EOF'\nopen('.claude/settings.json','w').write('{}')\nEOF",
		"python3 <<'EOF'\np='.claude/settings.json'; open(p,'w').write('{}')\nEOF",
		"node <<'EOF'\nrequire('fs').writeFileSync('.claude/settings.json','{}')\nEOF",
		"ruby <<'EOF'\nFile.write('.claude/settings.json','{}')\nEOF",
		`python3 <<< "open('.claude/settings.json','w').write('{}')"`,
		"sudo bash <<'EOF'\nrm .claude/settings.json\nEOF", "timeout 10 bash <<'EOF'\nrm .claude/settings.json\nEOF", "env bash <<'EOF'\nrm .claude/settings.json\nEOF", "cat <<'EOF' | sudo sh\nrm .claude/settings.json\nEOF", `bash <<< 'rm .claude/settings.json'`,
		`git ls-files -o > .claude/settings.json`, `ls -o > .claude/settings.json`, `jq . -o > .claude/settings.json`, `python3 -m json.tool x .claude/settings.json`,
		`shopt -s nullglob dotglob; rm -rf *`, `shopt -s  dotglob; rm -rf *`, `bash -O dotglob -c 'rm -rf *'`,
		`tar xzf a.tgz -C .claude`, `git -C .claude checkout settings.json`, `find . -fls .claude/settings.json`, `find . -fprint .claude/settings.json`, `find . -fprintf .claude/settings.json %p`, `unzip a.zip -d .claude`,
	}
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			assertHookConfigAsk(t, &harness.NormalizedToolCall{ToolName: "Bash", Command: command, Cwd: cwd})
		})
	}
}
func TestHookRoundFourPowerShell(t *testing.T) {
	for _, command := range []string{`rm .claude\settings.json`, `echo x > .claude\settings.json`, `cp x .claude\settings.json`, `mv .claude\settings.json x`, `ri .claude\settings.json`, `sc .claude\settings.json x`, `ni -Force .claude\settings.json`, `[IO.File]::WriteAllText('.claude\settings.json','{}')`, `[System.IO.File]::Delete('.claude\settings.json')`, `[IO.File]::Move('.claude\settings.json','x')`, `[IO.File]::Copy('x','.claude\settings.json')`, `mkdir -Force .claude\settings.json`, `md -Force .claude\settings.json`, `del .claude\settings.json`, `erase .claude\settings.json`, `rd .claude\settings.json`, `rmdir .claude\settings.json`, `copy x .claude\settings.json`, `cpi x .claude\settings.json`, `move .claude\settings.json x`, `mi .claude\settings.json x`, `ren .claude\settings.json x`, `rni .claude\settings.json x`, `ac .claude\settings.json x`, `Write-Output x > .claude\settings.json`, `echo x | Out-File .claude\settings.json`, `echo x | Tee-Object .claude\settings.json`} {
		for _, tool := range []string{"PowerShell", "Bash"} {
			t.Run(tool+command, func(t *testing.T) {
				assertHookConfigAsk(t, &harness.NormalizedToolCall{ToolName: tool, Command: command, Cwd: t.TempDir()})
			})
		}
		for _, shell := range []string{"powershell", "pwsh"} {
			assertHookConfigAsk(t, &harness.NormalizedToolCall{ToolName: "Bash", Command: shell + ` -Command "` + command + `"`, Cwd: t.TempDir()})
		}
	}
}
func TestHookRoundFourNoVerdicts(t *testing.T) {
	nav := ""
	for _, d := range []string{"d1", "d2", "d3", "d4", "d5"} {
		nav += "cd " + d + " && make && cd .. && "
	}
	nav += "true"
	for _, cwd := range []string{t.TempDir(), t.TempDir() + "/a/b", t.TempDir() + "/a/b/c/d"} {
		for _, command := range []string{nav, strings.Repeat("pushd a; make; popd; ", 6), `(cat .claude/settings.json)`, `python3 script.py <<'EOF'
.claude/settings.json
EOF`, `shopt -u dotglob; rm *`, `echo 'shopt -s dotglob'; rm *`, `tar czf a.tgz .claude`, `tar czf x -C .claude .`, `tar -cf x -C .claude .`, `git -C .claude status checkout`, `git -C .claude diff settings.json`, `git -C .claude status`, `find . -name settings.json`, `echo ordinary\text`, `mkdir src`, `python3 -m json.tool .claude/settings.json`} {
			if got := CheckAntiTampering(&harness.NormalizedToolCall{ToolName: "Bash", Command: command, Cwd: cwd}); got != nil {
				t.Errorf("%s: %+v", command, got)
			}
		}
	}
}
