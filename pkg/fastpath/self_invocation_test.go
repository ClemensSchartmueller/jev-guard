package fastpath

import (
	"jev-guard/pkg/harness"
	"testing"
)

func TestSelfInvocationReviewRegressions(t *testing.T) {
	deny := []string{
		`{ jev-guard ingest; }`, `if true; then jev-guard ingest; fi`, `for i in 1; do jev-guard ingest; done`, `while jev-guard ingest; do break; done`, `! jev-guard ingest`, `time jev-guard ingest`, `coproc jev-guard ingest`, `case x in x) jev-guard ingest;; esac`, `until jev-guard ingest; do break; done`, `cmd /c "echo ok & jev-guard ingest"`,
		`timeout 5 jev-guard ingest`, `nice jev-guard ingest`, `nice -n 5 jev-guard ingest`, `ionice -c 3 jev-guard ingest`, `stdbuf -o0 jev-guard ingest`, `setsid jev-guard ingest`, `chrt 1 jev-guard ingest`, `taskset 1 jev-guard ingest`, `watch -n 1 jev-guard ingest`, `strace -o log jev-guard ingest`, `ltrace jev-guard ingest`, `builtin command jev-guard ingest`, `busybox sh -c 'jev-guard ingest'`, `xargs jev-guard ingest`, `find . -exec jev-guard ingest \;`, `find . -execdir jev-guard ingest \;`, `parallel jev-guard ::: ingest`, `script -c 'jev-guard ingest' /dev/null`, `env -S 'jev-guard ingest'`, `env --split-string='jev-guard ingest'`,
		`npx -p @clemensschartmueller/jev-guard jev-guard ingest`, `npx --package=@clemensschartmueller/jev-guard jev-guard ingest`, `npx -q @clemensschartmueller/jev-guard ingest`, `npx --yes -q @clemensschartmueller/jev-guard ingest`, `npx -c 'jev-guard ingest'`, `npx --call 'jev-guard ingest'`, `npx --call='jev-guard ingest'`, `npm exec @clemensschartmueller/jev-guard -- ingest`, `npm x @clemensschartmueller/jev-guard -- ingest`, `pnpm dlx @clemensschartmueller/jev-guard ingest`, `pnpm exec jev-guard ingest`, `yarn dlx @clemensschartmueller/jev-guard ingest`, `bunx @clemensschartmueller/jev-guard ingest`, `bun x @clemensschartmueller/jev-guard ingest`, `npx jev-guard ingest`, `npx @ClemensSchartmueller/jev-guard ingest`,
		`jev-guard.cmd ingest`, `C:\Users\me\AppData\Roaming\npm\jev-guard.cmd ingest`, `jev-guard.ps1 ingest`, `jev-guard.bat ingest`, `node npm/jev-guard/bin/jev-guard.js ingest`, `Start-Process jev-guard -ArgumentList ingest`, `Start-Process -FilePath jev-guard -ArgumentList ingest`,
		`>/dev/null jev-guard ingest`, `jev-guard>/dev/null ingest`, `jev-guard 2>/dev/null ingest`, `jev-guard <in ingest`, `jev-guard ingest<<<'{"prompt":"x"}'`, `jev-guard ingest>/dev/null`,
		`echo 'jev-guard ingest' | sh`, `printf '%s' 'jev-guard ingest' | bash -s`, `sh <<< 'jev-guard ingest'`, `bash <<< "jev-guard ingest"`, "sh <<'EOF'\njev-guard ingest\nEOF", "bash -s <<EOF\njev-guard ingest\nEOF",
		`jev-gu?rd ingest`, `jev-guar[d] ingest`, `jev-{guard,x} ingest`,
	}
	ask := []string{`echo ingest | xargs jev-guard`, `yarn jev-guard`, `~/.local/bin/jev-*`, `Start-Process jev-guard`}
	negative := []string{
		`echo 'run: (jev-guard clear-intent --all)'`, `git commit -m 'block x && jev-guard ingest'`, `grep -E 'a|jev-guard status' docs/cli.md`,
		"cat > notes.md <<'EOF'\njev-guard ingest --session x\nEOF", "git commit -F - <<'EOF'\ntext\njev-guard clear-intent --all is now denied\nEOF", "gh pr create --body \"$(cat <<'EOF'\ntext\njev-guard ingest --prompt x\nEOF\n)\"",
		`command -v jev-guard`, `command -V jev-guard`, `ls -l $(command -v jev-guard)`, `which jev-guard`, `type jev-guard`, `echo 'jev-guard ingest'; sh`, "cat <<EOF\njev-guard ingest\nEOF\nsh",
	}
	for _, group := range []struct {
		commands []string
		want     harness.Decision
	}{{deny, harness.DecisionDeny}, {ask, harness.DecisionAsk}, {negative, ""}} {
		for _, cmd := range group.commands {
			t.Run(cmd, func(t *testing.T) {
				got := checkSelfInvocation(&harness.NormalizedToolCall{Command: cmd})
				if group.want == "" {
					if got != nil {
						t.Fatalf("got %+v", got)
					}
				} else if got == nil || got.Decision != group.want {
					t.Fatalf("got %+v, want %s", got, group.want)
				}
			})
		}
	}
}
