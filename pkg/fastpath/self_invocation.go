package fastpath

import (
	"path"
	"strings"

	"jev-guard/pkg/harness"
)

// SourceSelfInvocation identifies deterministic decisions about agent CLI execution.
const SourceSelfInvocation = "fastpath_self_invocation"
const pipelineSeparator = "\x00pipeline-boundary\x00"
const commandSeparator = "\x00command-boundary\x00"

// checkSelfInvocation checks executable positions, rather than mentions in operands.
// It shares the shell reader's bounds and nested-payload recognition. It only sees
// agent tool calls; starting the real hook process never goes through this rule.
func checkSelfInvocation(call *harness.NormalizedToolCall) *harness.EvaluationResult {
	r := newShellReader()
	var result *harness.EvaluationResult
	record := func(words []string) {
		decision := guardInvocationDecision(words)
		if decision == "" || (result != nil && result.Decision == harness.DecisionDeny) {
			return
		}
		reason := "Agent invocation of the jev-guard CLI requires user approval"
		if decision == harness.DecisionDeny {
			reason = "Agent invocation of state-changing jev-guard CLI commands is prohibited"
		}
		result = &harness.EvaluationResult{Decision: decision, Reason: reason, Source: SourceSelfInvocation, Confidence: 1}
	}
	var visit func(string, int, bool)
	visit = func(text string, depth int, windows bool) {
		if len(text) > maxGuardCommandBytes || !r.spend(len(text), 0) {
			r.exhausted = true
			return
		}
		clean := stripHeredocBodies(text)
		p, _, _ := posixRead(clean, false, true)
		ps, _, _ := powerShellRead(clean, false, true)
		readings := [][]string{p, ps}
		if windows {
			cmd, _ := cmdRead(text, true)
			readings = [][]string{cmd}
		}
		for _, words := range readings {
			if !r.spend(0, len(words)) {
				return
			}
			start := 0
			for i := 0; i <= len(words); i++ {
				if i < len(words) && words[i] != commandSeparator && words[i] != pipelineSeparator {
					continue
				}
				segment := words[start:i]
				record(segment)
				for _, payload := range append(selfInvocationPayloads(r, segment), shellInputPayloads(text, words[:start], segment)...) {
					if depth >= maxShellNesting {
						r.tooDeep = true
						continue
					}
					unwrapped := unwrapInvocation(segment)
					visit(payload, depth+1, len(unwrapped) > 0 && programName(unwrapped[0]) == "cmd")
				}
				start = i + 1
			}
		}
		for _, payload := range commandSubstitutions(clean) {
			if depth >= maxShellNesting {
				r.tooDeep = true
				continue
			}
			if r.spendPayload(len(payload)) {
				visit(payload, depth+1, false)
			}
		}
	}
	visit(call.Command, 0, false)
	for _, key := range commandArgKeys {
		if text, ok := call.RawArgs[key].(string); ok {
			if text != call.Command {
				visit(text, 0, false)
			}
		} else {
			words := stringValues(call.RawArgs[key])
			size := 0
			for _, word := range words {
				size += len(word)
			}
			if !r.spend(size, len(words)) {
				continue
			}
			record(words)
			for _, payload := range selfInvocationPayloads(r, words) {
				visit(payload, 1, false)
			}
		}
	}
	if result != nil && result.Decision == harness.DecisionDeny {
		return result
	}
	if limit := r.incomplete(); limit != "" {
		return &harness.EvaluationResult{Decision: harness.DecisionAsk, Reason: "Guard CLI invocation could not be verified: " + limit, Source: SourceAntiTamperingLimit, Confidence: 1}
	}
	return result
}

// Wrapper option values must not be mistaken for executable names.
var wrapperValues = map[string]string{
	"env":     "-u --unset -C --chdir -S --split-string",
	"command": "",
	"builtin": "",
	"exec":    "-a",
	"sudo":    "-u -g -h -C -T -p --user --group --host --chdir",
	"doas":    "-u -C",
	"nohup":   "",
	"timeout": "-s --signal -k --kill-after",
	"nice":    "-n --adjustment",
	"ionice":  "-c --class -n --classdata -p --pid -P --pgid -u --uid",
	"stdbuf":  "-i -o -e --input --output --error",
	"setsid":  "",
	"chrt":    "-p --pid",
	"taskset": "-p --pid",
	"watch":   "-n --interval",
	"strace":  "-o -e -p -s -u -P --output --trace --attach",
	"ltrace":  "-o -e -p -s -u -l",
	"xargs":   "-a -E -I -L -n -P -s --arg-file --eof --replace --max-lines --max-args --max-procs --max-chars",
}

func unwrapInvocation(words []string) []string {
	for len(words) > 0 {
		word := words[0]
		if assignment := strings.IndexByte(word, '='); assignment > 0 && !strings.ContainsAny(word[:assignment], `/\-`) {
			words = words[1:]
			continue
		}
		name := programName(word)
		switch name {
		case "{", "!", "time", "coproc", "if", "then", "elif", "else", "do", "while", "until":
			words = words[1:]
			continue
		case "busybox":
			words = words[1:]
			continue
		case "find":
			for i, w := range words {
				if w == "-exec" || w == "-execdir" {
					return unwrapInvocation(words[i+1:])
				}
			}
			return nil
		}
		values, ok := wrapperValues[name]
		if !ok {
			return words
		}
		words = words[1:]
		for len(words) > 0 && strings.HasPrefix(words[0], "-") {
			flag := words[0]
			words = words[1:]
			if name == "command" && (flag == "-v" || flag == "-V") {
				return nil
			}
			key, _, attached := strings.Cut(flag, "=")
			if strings.Contains(" "+values+" ", " "+key+" ") && !attached && len(words) > 0 {
				if name == "env" && (key == "-S" || key == "--split-string") {
					payload, _, _ := posixRead(words[0], false)
					words = append(payload, words[1:]...)
					break
				}
				words = words[1:]
			} else if name == "env" && key == "--split-string" && attached {
				payload, _, _ := posixRead(strings.TrimPrefix(flag, key+"="), false)
				words = append(payload, words...)
				break
			}
		}
		if (name == "timeout" || name == "chrt" || name == "taskset") && len(words) > 0 {
			words = words[1:]
		}
	}
	return nil
}

// Shell stdin is executable only when a shell occupies command position.
func shellInputPayloads(text string, all, segment []string) []string {
	w := unwrapInvocation(segment)
	if len(w) == 0 || !shellPrograms[programName(w[0])] {
		return nil
	}
	for _, a := range w[1:] {
		if strings.Contains(a, "c") && strings.HasPrefix(a, "-") {
			return nil
		}
	}
	var out []string
	// Associate stdin redirections with their receiving command, not another
	// command in the same script.
	if i := strings.Index(text, "<<"); i >= 0 {
		head, _, _ := posixRead(text[:i], false, true)
		start := 0
		for j, a := range head {
			if a == commandSeparator || a == pipelineSeparator {
				start = j + 1
			}
		}
		receiver := unwrapInvocation(head[start:])
		if len(receiver) > 0 && shellPrograms[programName(receiver[0])] {
			if strings.HasPrefix(text[i:], "<<<") {
				args, _, _ := posixRead(text[i+3:], false)
				out = append(out, args...)
			} else {
				lines := strings.Split(text[i:], "\n")
				if len(lines) > 1 {
					out = append(out, strings.Join(lines[1:], "\n"))
				}
			}
		}
	}
	// Only stages joined by a pipe provide stdin. A preceding semicolon does not.
	start, end := 0, len(all)
	for i := 0; i < len(all); i++ {
		if all[i] == commandSeparator {
			start = i + 1
		}
	}
	if end > start && all[end-1] == pipelineSeparator {
		for _, a := range all[start : end-1] {
			if a != pipelineSeparator {
				out = append(out, a)
			}
		}
	}
	return out
}

// Read interpreter payloads only when the interpreter occupies an executable
// position. For example, echo sh -c 'jev-guard ingest' merely prints data.
func selfInvocationPayloads(r *shellReader, words []string) []string {
	words = unwrapInvocation(words)
	if len(words) == 0 {
		return nil
	}
	name := programName(words[0])
	if name == "script" {
		for i, a := range words {
			if (a == "-c" || a == "--command") && i+1 < len(words) {
				return []string{words[i+1]}
			}
		}
	}
	if name == "npx" {
		for i, a := range words {
			if strings.HasPrefix(a, "--call=") {
				return []string{strings.TrimPrefix(a, "--call=")}
			}
			if (a == "-c" || a == "--call") && i+1 < len(words) {
				return []string{words[i+1]}
			}
		}
	}
	if !shellPrograms[name] && name != "eval" && name != "cmd" && name != "powershell" && name != "pwsh" {
		return nil
	}
	return r.commandPayloads(words)
}

func guardInvocationDecision(words []string) harness.Decision {
	words = unwrapInvocation(words)
	if len(words) > 0 {
		name := programName(words[0])
		switch name {
		case "npx", "bunx", "npm", "pnpm", "yarn", "bun":
			words = words[1:]
			if len(words) > 0 && (words[0] == "exec" || words[0] == "x" || words[0] == "dlx") {
				words = words[1:]
			}
			for len(words) > 0 && strings.HasPrefix(words[0], "-") {
				f := words[0]
				words = words[1:]
				if (f == "-p" || f == "--package") && len(words) > 0 {
					words = words[1:]
				}
			}
			if len(words) == 0 {
				return ""
			}
			pkg := strings.ToLower(words[0])
			if pkg == "@clemensschartmueller/jev-guard" || strings.HasPrefix(pkg, "@clemensschartmueller/jev-guard@") {
				words[0] = "jev-guard"
			}
			if len(words) > 1 && words[1] == "--" {
				words = append(words[:1], words[2:]...)
			}
		case "node":
			if len(words) < 2 || programName(words[1]) != "jev-guard.js" {
				return ""
			}
			words = words[1:]
			words[0] = "jev-guard"
		case "start-process":
			words = words[1:]
			if len(words) > 0 && strings.EqualFold(words[0], "-FilePath") {
				words = words[1:]
			}
			if len(words) > 2 && strings.EqualFold(words[1], "-ArgumentList") {
				words = append(words[:1], words[2:]...)
			}
		case "parallel":
			words = words[1:]
			if len(words) > 1 && words[1] == ":::" {
				words = append(words[:1], words[2:]...)
			}
		}
		if len(words) == 0 {
			return ""
		}
		name = programName(words[0])
		for _, ext := range []string{".cmd", ".bat", ".ps1"} {
			name = strings.TrimSuffix(name, ext)
		}
		match := name == "jev-guard"
		patterns, _ := expandBraces(name, 64)
		for _, pattern := range patterns {
			for _, target := range []string{"jev-guard", "jev-guard.exe"} {
				ok, _ := path.Match(pattern, target)
				match = match || ok
			}
		}
		if !match {
			return ""
		}
		args := words[1:]
		if len(args) == 0 {
			return harness.DecisionAsk
		}
		switch strings.ToLower(args[0]) {
		case "--version", "-version", "-v", "version", "--help", "-help", "-h", "help":
			return ""
		case "ingest", "end-turn", "end_turn", "clear-intent", "clear_intent", "init":
			return harness.DecisionDeny
		case "cache":
			if len(args) > 1 && strings.EqualFold(args[1], "clear") {
				return harness.DecisionDeny
			}
		case "config":
			if len(args) > 1 && (strings.EqualFold(args[1], "trust") || strings.EqualFold(args[1], "untrust")) {
				return harness.DecisionDeny
			}
		}
		// Unknown commands also require approval, making future CLI additions fail closed.
		return harness.DecisionAsk
	}
	return ""
}
