package fastpath

import (
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

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
	return checkSelfInvocationUntil(call, time.Now().Add(250*time.Millisecond))
}

func checkSelfInvocationUntil(call *harness.NormalizedToolCall, deadline time.Time) *harness.EvaluationResult {
	r := newShellReader()
	r.deadline = deadline
	var result *harness.EvaluationResult
	record := func(words []string) {
		decision := guardInvocationDecision(words, r)
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
		bodies := map[string]string{}
		var substitutions []string
		count := 0
		if !r.spend(len(text), 0) {
			return
		}
		clean := readHeredocs(text, func(body string, quoted bool) string {
			if body == "" {
				count++
				marker := "__guard_stdin_" + strconv.Itoa(count) + "__"
				bodies[marker] = ""
				return marker
			}
			marker, value, _ := strings.Cut(body, "\x00")
			bodies[marker] = value
			if !quoted && r.spend(len(value), 0) {
				substitutions = append(substitutions, commandSubstitutions(value, true)...)
			}
			return ""
		}, r)
		if !r.spend(2*len(clean), 0) {
			return
		}
		p, _, _ := posixRead(clean, false, true)
		ps, _, _ := powerShellRead(clean, false, true)
		readings := [][]string{p, ps}
		if windows {
			if !r.spend(len(text), 0) {
				return
			}
			cmd, _ := cmdRead(text, true)
			readings = [][]string{cmd}
		}
		for _, words := range readings {
			if len(words) > 0 && words[len(words)-1] == pipelineSeparator {
				r.exhausted = true
			}
			if !r.spend(0, len(words)) {
				return
			}
			start := 0
			var upstream []string
			for i := 0; i <= len(words); i++ {
				if i < len(words) && words[i] != commandSeparator && words[i] != pipelineSeparator {
					continue
				}
				if !r.spend(0, i-start+1) {
					return
				}
				segment := make([]string, 0, i-start)
				var stdin []string
				for _, word := range words[start:i] {
					if body, ok := bodies[word]; ok {
						stdin = append(stdin, body)
					} else {
						segment = append(segment, word)
					}
				}
				record(segment)
				payloads := selfInvocationPayloads(r, segment)
				w := unwrapInvocation(segment, r)
				if len(w) > 0 && shellPrograms[programName(w[0])] && !hasCommandFlag(w[1:]) {
					payloads = append(payloads, stdin...)
					payloads = append(payloads, upstream...)
				}
				for _, payload := range payloads {
					if !r.spendPayload(len(payload)) {
						break
					}
					if depth >= maxShellNesting {
						r.tooDeep = true
						continue
					}
					unwrapped := unwrapInvocation(segment, r)
					visit(payload, depth+1, len(unwrapped) > 0 && programName(unwrapped[0]) == "cmd")
				}
				// Keep only the immediately preceding stage. This is linear even
				// for pipelines containing thousands of shell stages.
				upstream = nil
				if i < len(words) && words[i] == pipelineSeparator {
					upstream = append(upstream, stdin...)
					size := 0
					for _, word := range segment {
						size += len(word) + 1
					}
					if r.spend(2*size, len(segment)) {
						upstream = append(upstream, strings.Join(segment, " "))
						if len(segment) > 1 {
							upstream = append(upstream, segment[1:]...)
							upstream = append(upstream, strings.Join(segment[1:], " "))
						}
					}
				}
				start = i + 1
			}
		}
		if !r.spend(len(clean), 0) {
			return
		}
		for _, payload := range append(substitutions, commandSubstitutions(clean)...) {
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
				if !r.spendPayload(len(payload)) {
					break
				}
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
	"time":    "-o --output -f --format",
	"call":    "",
	"start":   "",
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

func unwrapInvocation(words []string, readers ...*shellReader) []string {
	r := newShellReader()
	if len(readers) > 0 {
		r = readers[0]
	}
	for len(words) > 0 {
		if !r.spend(0, 1) {
			return nil
		}
		word := words[0]
		if assignment := strings.IndexByte(word, '='); assignment > 0 && !strings.ContainsAny(word[:assignment], `/\-`) {
			words = words[1:]
			continue
		}
		name := programName(word)
		switch name {
		case "function":
			if len(words) > 2 {
				words = words[2:]
				continue
			}
			return nil
		case ".":
			if len(words) > 1 && programName(words[1]) == "jev-guard" {
				words = words[1:]
				continue
			}
			return words
		case "{", "!", "coproc", "if", "then", "elif", "else", "do", "while", "until":
			words = words[1:]
			continue
		case "busybox":
			words = words[1:]
			continue
		case "find":
			for i, w := range words {
				if w == "-exec" || w == "-execdir" {
					return unwrapInvocation(words[i+1:], r)
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
			if name == "env" && strings.HasPrefix(flag, "-S") && len(flag) > 2 {
				if !r.spend(len(flag), 0) {
					return nil
				}
				payload, _, _ := posixRead(flag[2:], false)
				words = append(payload, words...)
				break
			}
			if name == "command" && (flag == "-v" || flag == "-V") {
				return nil
			}
			key, _, attached := strings.Cut(flag, "=")
			if strings.Contains(" "+values+" ", " "+key+" ") && !attached && len(words) > 0 {
				if name == "env" && (key == "-S" || key == "--split-string") {
					if !r.spend(len(words[0]), 0) {
						return nil
					}
					payload, _, _ := posixRead(words[0], false)
					words = append(payload, words[1:]...)
					break
				}
				words = words[1:]
			} else if name == "env" && key == "--split-string" && attached {
				if !r.spend(len(flag), 0) {
					return nil
				}
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

var commandFlag = regexp.MustCompile(`^-[A-Za-z]*c[A-Za-z]*$`)

func hasCommandFlag(args []string) bool {
	for _, a := range args {
		if a == "--command" || strings.HasPrefix(a, "--command=") || commandFlag.MatchString(a) {
			return true
		}
	}
	return false
}

// Read interpreter payloads only when the interpreter occupies an executable
// position. For example, echo sh -c 'jev-guard ingest' merely prints data.
func selfInvocationPayloads(r *shellReader, words []string) []string {
	if !r.spend(0, len(words)) {
		return nil
	}
	words = unwrapInvocation(words, r)
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
	if !shellPrograms[name] && name != "eval" && name != "iex" && name != "invoke-expression" && name != "cmd" && name != "powershell" && name != "pwsh" {
		return nil
	}
	if name == "iex" || name == "invoke-expression" {
		return words[1:]
	}
	return r.commandPayloads(words)
}

func guardInvocationDecision(words []string, readers ...*shellReader) harness.Decision {
	words = unwrapInvocation(words, readers...)
	if len(words) > 0 {
		name := programName(words[0])
		switch name {
		case "npx", "bunx", "npm", "pnpm", "yarn", "bun":
			words = words[1:]

			for len(words) > 0 {
				if words[0] == "exec" || words[0] == "x" || words[0] == "dlx" {
					words = words[1:]
					continue
				}
				if !strings.HasPrefix(words[0], "-") {
					break
				}
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
			words = words[1:]
			for len(words) > 0 && strings.HasPrefix(words[0], "-") {
				words = words[1:]
			}
			if len(words) == 0 || (programName(words[0]) != "jev-guard.js" && programName(words[0]) != "jev-guard") {
				return ""
			}
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
				ok, _ := path.Match(strings.ReplaceAll(pattern, "[!", "[^"), target)
				match = match || ok
			}
		}
		if !match {
			if strings.Contains(name, "[") && name != "[" && name != "[[" {
				return harness.DecisionAsk
			}
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
