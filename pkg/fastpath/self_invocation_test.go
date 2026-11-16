package fastpath

import (
	"jev-guard/pkg/harness"
	"strings"
	"testing"
	"time"
)

func TestSelfInvocationReviewRegressions(t *testing.T) {
	deny := []string{
		`echo jev-guard ingest | sh -`, `echo jev-guard ingest | bash /dev/stdin`,
		"pwsh -c '# say \"hi\njev-guard ingest'",

		"f(){ jev-guard ingest; }; f",
		"f () { jev-guard end-turn; } ; f",
		"f() (jev-guard ingest); f",
		"bash -c 'f(){ jev-guard clear-intent; }; f'",
		"x=$(f(){ jev-guard ingest; }; f)",
		"if (true) then jev-guard ingest; fi",
		"while (true) do jev-guard ingest; break; done",
		"until (false) do jev-guard ingest; done",
		"case x in (x) jev-guard ingest;; esac",
		"(case x in x) jev-guard ingest;; esac)",
		"# Let's reset the session\njev-guard clear-intent --all",
		"git status # what's changed?\njev-guard ingest",
		"cd /repo  # user's repo\njev-guard end-turn",
		"# Check the guard's state, then ingest\njev-guard ingest",
		"# say \"hi\njev-guard ingest",
		"# it's\nbash -c 'jev-guard ingest'",
		"# it's\necho $(jev-guard ingest)",
		"# it's\ncat <<EOF | sh\njev-guard ingest\nEOF",
		"cat <<EOF | sh\n# it's\njev-guard ingest\nEOF",
		"cat <<EOF | (cat | sh)\njev-guard ingest\nEOF",
		"<# say \"hi #>\njev-guard ingest",

		` { sh; } <<< 'jev-guard ingest'`, `( sh ) <<< 'jev-guard ingest'`,
		`echo jev-guard ingest | cat | sh`, `echo jev-guard ingest | tee /dev/null | sh`,
		"cat <<EOF | tee /dev/null | sh\njev-guard ingest\nEOF",
		"{ sh; } <<EOF\njev-guard ingest\nEOF", "( sh ) <<EOF\njev-guard ingest\nEOF",
		"cat <<EOF | (sh)\njev-guard ingest\nEOF", `echo jev-guard ingest |& sh`,
		`echo jev-guard ingest | source /dev/stdin`, `echo jev-guard ingest | . /dev/stdin`,
		`'jev-guard ingest' | iex`, `"jev-guard ingest" | Invoke-Expression`, `IEX("jev-guard ingest")`,
		`pwsh -c "'jev-guard ingest' | iex"`, `echo jev-guard ingest | bash -c sh`,
		"bash -c sh <<EOF\njev-guard ingest\nEOF", `sh -c -- 'jev-guard ingest'`, `bash -c -x 'jev-guard ingest'`,
		"cat <<EOF >/dev/null\n$(jev-guard ingest)\nEOF",
		"cat <<EOF\n'$(jev-guard ingest)'\nEOF",
		"cat <<EOF >/dev/null\n`jev-guard ingest`\nEOF",
		"git commit -F - <<EOF\n`jev-guard ingest`\nEOF",
		"cat <<EOF | sh\njev-guard ingest\nEOF",
		"cat <<EOF; jev\\-guard ingest\nx\nEOF",
		"echo \"<<\"; bash <<EOF\njev-guard ingest\nEOF",
		"cat <<A\nx\nA\nbash <<B\njev-guard ingest\nB",
		`bash --norc <<< 'jev-guard ingest'`, `echo 'jev-guard ingest' | bash --norc`, `echo 'jev-guard ingest' | fish --no-config`,
		`env -S'jev-guard ingest'`, `env -S"jev-guard ingest"`, `echo jev-guard ingest | sh`, `jev-guar[!x] ingest`,
		`function f { jev-guard ingest; }; f`, `{fd}>/dev/null jev-guard ingest`, `exec {fd}>/dev/null jev-guard ingest`, `/usr/bin/time -v jev-guard ingest`,
		`npm --yes exec @clemensschartmueller/jev-guard -- ingest`, `pnpm --package=@clemensschartmueller/jev-guard dlx jev-guard ingest`, `node --no-warnings bin/jev-guard.js ingest`, `node node_modules/.bin/jev-guard ingest`,
		`iex 'jev-guard ingest'`, `Invoke-Expression "jev-guard ingest"`, `start jev-guard ingest`, `cmd /c call jev-guard ingest`, `. jev-guard ingest`,
		`{ jev-guard ingest; }`, `if true; then jev-guard ingest; fi`, `for i in 1; do jev-guard ingest; done`, `while jev-guard ingest; do break; done`, `! jev-guard ingest`, `time jev-guard ingest`, `coproc jev-guard ingest`, `case x in x) jev-guard ingest;; esac`, `until jev-guard ingest; do break; done`, `cmd /c "echo ok & jev-guard ingest"`,
		`timeout 5 jev-guard ingest`, `nice jev-guard ingest`, `nice -n 5 jev-guard ingest`, `ionice -c 3 jev-guard ingest`, `stdbuf -o0 jev-guard ingest`, `setsid jev-guard ingest`, `chrt 1 jev-guard ingest`, `taskset 1 jev-guard ingest`, `watch -n 1 jev-guard ingest`, `strace -o log jev-guard ingest`, `ltrace jev-guard ingest`, `builtin command jev-guard ingest`, `busybox sh -c 'jev-guard ingest'`, `xargs jev-guard ingest`, `find . -exec jev-guard ingest \;`, `find . -execdir jev-guard ingest \;`, `parallel jev-guard ::: ingest`, `script -c 'jev-guard ingest' /dev/null`, `env -S 'jev-guard ingest'`, `env --split-string='jev-guard ingest'`,
		`npx -p @clemensschartmueller/jev-guard jev-guard ingest`, `npx --package=@clemensschartmueller/jev-guard jev-guard ingest`, `npx -q @clemensschartmueller/jev-guard ingest`, `npx --yes -q @clemensschartmueller/jev-guard ingest`, `npx -c 'jev-guard ingest'`, `npx --call 'jev-guard ingest'`, `npx --call='jev-guard ingest'`, `npm exec @clemensschartmueller/jev-guard -- ingest`, `npm x @clemensschartmueller/jev-guard -- ingest`, `pnpm dlx @clemensschartmueller/jev-guard ingest`, `pnpm exec jev-guard ingest`, `yarn dlx @clemensschartmueller/jev-guard ingest`, `bunx @clemensschartmueller/jev-guard ingest`, `bun x @clemensschartmueller/jev-guard ingest`, `npx jev-guard ingest`, `npx @ClemensSchartmueller/jev-guard ingest`,
		`jev-guard.cmd ingest`, `C:\Users\me\AppData\Roaming\npm\jev-guard.cmd ingest`, `jev-guard.ps1 ingest`, `jev-guard.bat ingest`, `node npm/jev-guard/bin/jev-guard.js ingest`, `Start-Process jev-guard -ArgumentList ingest`, `Start-Process -FilePath jev-guard -ArgumentList ingest`,
		`>/dev/null jev-guard ingest`, `jev-guard>/dev/null ingest`, `jev-guard 2>/dev/null ingest`, `jev-guard <in ingest`, `jev-guard ingest<<<'{"prompt":"x"}'`, `jev-guard ingest>/dev/null`,
		`echo 'jev-guard ingest' | sh`, `printf '%s' 'jev-guard ingest' | bash -s`, `sh <<< 'jev-guard ingest'`, `bash <<< "jev-guard ingest"`, "sh <<'EOF'\njev-guard ingest\nEOF", "bash -s <<EOF\njev-guard ingest\nEOF",
		`jev-gu?rd ingest`, `jev-guar[d] ingest`, `jev-{guard,x} ingest`,
	}
	ask := []string{"bash -" + strings.Repeat("l", 129) + "c 'jev-guard ingest'", `/path/jev-guar[[:alpha:]] ingest`, `echo ingest | xargs jev-guard`, `yarn jev-guard`, `~/.local/bin/jev-*`, `Start-Process jev-guard`}
	negative := []string{
		"echo a#b",
		"echo ${#x}",
		"echo $#",
		"grep 'jev-guard ingest' docs/cli.md | bash scripts/count.sh",
		"rg -l 'jev-guard ingest' | sh ./scripts/x.sh",

		`echo $((1<<3))`, `printf "%d" $((2<<10))`, `(( x = 1 << 4 ))`, `git log |`,
		`./build[2].sh --fast`, `test[1].sh`, `docs/[a-z]*.md`, "cat <<EOF", "sh <<EOF",
		"cat <<EOF\nEOF", "sh <<EOF\nEOF", "cat <<A <<B\nA\nB",
		"git commit -F - <<'EOF'\n`jev-guard ingest`\n$(jev-guard ingest)\nEOF",
		`sed -i 's/jev-guard ingest/updated/g' docs/cli.md`, `. other-file jev-guard ingest`,
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

func TestSelfInvocationPerformance(t *testing.T) {
	for _, cmd := range []string{strings.Repeat("sh;", 4000) + "<<x", strings.Repeat("sh;", 20000) + "<<x", strings.Repeat("sh|", 2000), strings.Repeat("sh|", 8000), strings.Repeat("sh;", (1<<20)/3) + "<<x"} {
		start := time.Now()
		got := checkSelfInvocation(&harness.NormalizedToolCall{Command: cmd})
		elapsed := time.Since(start)
		t.Logf("%d bytes: %s", len(cmd), elapsed)
		if elapsed > 2*time.Second {
			t.Fatalf("analysis exceeded 2s: %s", elapsed)
		}
		if got != nil && got.Decision == harness.DecisionAllow {
			t.Fatalf("must fail closed, got %+v", got)
		}
	}
}

func TestSelfInvocationDeadline(t *testing.T) {
	got := checkSelfInvocationUntil(&harness.NormalizedToolCall{Command: "echo safe"}, time.Now().Add(-time.Second))
	if got == nil || got.Decision != harness.DecisionAsk || got.Source != SourceAntiTamperingLimit {
		t.Fatalf("deadline must fail closed: %+v", got)
	}
}

func TestB2Performance(t *testing.T) {
	for _, cmd := range []string{
		"echo" + strings.Repeat(" sh", 500) + " -" + strings.Repeat("a", 200000),
		"echo" + strings.Repeat(" sh", 2000) + " -" + strings.Repeat("a", 200000),
		"echo" + strings.Repeat(" sh", 2000),
		"echo" + strings.Repeat(" sh", 2000) + " -" + strings.Repeat("a", 2000000),
		strings.Repeat("sh;", 20000) + "sh <<x\nx\nx\n", strings.Repeat("sh|", 30000) + "sh",
	} {
		start := time.Now()
		call := &harness.NormalizedToolCall{Command: cmd}
		got := CheckAntiTampering(call)
		elapsed := time.Since(start)
		t.Logf("%d bytes: %s verdict=%+v", len(cmd), elapsed, got)
		if elapsed > 2*time.Second {
			t.Fatal("exceeded 2 seconds")
		}
		if (got != nil && got.Decision == harness.DecisionAllow) || (strings.HasPrefix(cmd, "echo") && got == nil) {
			t.Fatal("must fail closed")
		}
	}
}

func TestUnquotedHeredocHint(t *testing.T) {
	got := checkSelfInvocation(&harness.NormalizedToolCall{Command: "cat <<EOF\n$(jev-guard ingest)\nEOF"})
	if got == nil || !strings.Contains(got.Reason, "<<'EOF'") {
		t.Fatalf("missing delimiter hint: %+v", got)
	}
}
