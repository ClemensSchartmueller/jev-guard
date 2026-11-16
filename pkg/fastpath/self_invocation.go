package fastpath

import (
	"strings"

	"jev-guard/pkg/harness"
)

// SourceSelfInvocation identifies deterministic decisions about agent CLI execution.
const SourceSelfInvocation = "fastpath_self_invocation"
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
	var visit func(string, int)
	visit = func(text string, depth int) {
		if len(text) > maxGuardCommandBytes || !r.spend(len(text), 0) {
			r.exhausted = true
			return
		}
		p, _, _ := posixRead(text, false, true)
		ps, _, _ := powerShellRead(text, false, true)
		cmd, _ := cmdRead(text, true)
		for _, words := range [][]string{p, ps, cmd} {
			if !r.spend(0, len(words)) {
				return
			}
			start := 0
			for i := 0; i <= len(words); i++ {
				if i < len(words) && words[i] != commandSeparator {
					continue
				}
				segment := words[start:i]
				record(segment)
				for _, payload := range selfInvocationPayloads(r, segment) {
					if depth >= maxShellNesting {
						r.tooDeep = true
						continue
					}
					visit(payload, depth+1)
				}
				start = i + 1
			}
		}
		for _, payload := range commandSubstitutions(text) {
			if depth >= maxShellNesting {
				r.tooDeep = true
				continue
			}
			if r.spendPayload(len(payload)) {
				visit(payload, depth+1)
			}
		}
	}
	visit(call.Command, 0)
	for _, key := range commandArgKeys {
		if text, ok := call.RawArgs[key].(string); ok {
			if text != call.Command {
				visit(text, 0)
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
				visit(payload, 1)
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

func unwrapInvocation(words []string) []string {
	for len(words) > 0 {
		word := words[0]
		if assignment := strings.IndexByte(word, '='); assignment > 0 && !strings.ContainsAny(word[:assignment], `/\\-`) {
			words = words[1:]
			continue
		}
		name := programName(word)
		switch name {
		case "env", "command", "exec", "sudo", "doas", "nohup":
			words = words[1:]
			for len(words) > 0 && strings.HasPrefix(words[0], "-") {
				flag := words[0]
				words = words[1:]
				switch flag {
				case "-u", "-g", "-h", "-C", "-T", "--user", "--group", "--host", "--chdir", "--unset":
					if len(words) > 0 {
						words = words[1:]
					}
				case "-p", "-a":
					if ((name == "sudo" && flag == "-p") || (name == "exec" && flag == "-a")) && len(words) > 0 {
						words = words[1:]
					}
				}
			}
			continue
		default:
			return words
		}
	}
	return nil
}

// Read interpreter payloads only when the interpreter occupies an executable
// position. For example, echo sh -c 'jev-guard ingest' merely prints data.
func selfInvocationPayloads(r *shellReader, words []string) []string {
	words = unwrapInvocation(words)
	if len(words) == 0 {
		return nil
	}
	name := programName(words[0])
	if !shellPrograms[name] && name != "eval" && name != "cmd" && name != "powershell" && name != "pwsh" && len(interpreterFlags[interpreterName(name)]) == 0 {
		return nil
	}
	return r.commandPayloads(words)
}

func guardInvocationDecision(words []string) harness.Decision {
	words = unwrapInvocation(words)
	if len(words) > 0 {
		switch programName(words[0]) {
		case "npx":
			words = words[1:]
			if len(words) > 0 && (words[0] == "--yes" || words[0] == "-y") {
				words = words[1:]
			}
			if len(words) == 0 {
				return ""
			}
			pkg := words[0]
			if pkg != "@clemensschartmueller/jev-guard" && !strings.HasPrefix(pkg, "@clemensschartmueller/jev-guard@") {
				return ""
			}
		case "jev-guard":
		default:
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
