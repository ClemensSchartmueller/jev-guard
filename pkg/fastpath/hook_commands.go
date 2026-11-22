package fastpath

import (
	"path/filepath"
	"strings"
)

// Split only unquoted shell control operators; preserve quoted interpreter payloads.
func hookSegments(command string) []string {
	parts, _ := hookSegmentsWithScopes(command)
	return parts
}

func hookSegmentsWithScopes(command string) ([]string, map[int]bool) {
	var patternClosers map[int]bool
	command = hookMaskComments(command, false, false)
	var parts []string
	start := 0
	contentStart := 0
	var quote byte
	escaped := false
	substitutionDepth := 0
	methodDepth := 0
	parenDepth := 0
	var cases []int
	for i := 0; i < len(command); i++ {
		c := command[i]
		if i == contentStart && isShellSpace(c) {
			contentStart++
		}
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if c == '(' && i > 0 && command[i-1] == '$' {
			substitutionDepth++
			continue
		}
		if substitutionDepth > 0 {
			if c == '(' {
				substitutionDepth++
			}
			if c == ')' {
				substitutionDepth--
			}
			continue
		}
		if i == contentStart {
			for _, keyword := range []string{"case", "esac"} {
				if strings.HasPrefix(command[i:], keyword) && (i+len(keyword) == len(command) || isShellSpace(command[i+len(keyword)]) || strings.ContainsRune(";)", rune(command[i+len(keyword)]))) {
					if keyword == "case" {
						cases = append(cases, parenDepth)
					} else if len(cases) > 0 {
						cases = cases[:len(cases)-1]
					}
				}
			}
		}
		patternCloser := c == ')' && len(cases) > 0 && parenDepth == cases[len(cases)-1]
		if patternCloser {
			if patternClosers == nil {
				patternClosers = map[int]bool{}
			}
			patternClosers[i] = true
		}
		prefix := ""
		if c == '(' {
			prefix = strings.ToLower(command[contentStart:min(i, contentStart+18)])
		}
		if c == '(' && (methodDepth > 0 || strings.HasPrefix(prefix, "[io.file]::") || strings.HasPrefix(prefix, "[system.io.file]::")) {
			methodDepth++
			continue
		}
		if methodDepth > 0 {
			if c == ')' {
				methodDepth--
			}
			continue
		}
		if c == '(' {
			parenDepth++
		}
		if c == ')' && parenDepth > 0 && !patternCloser {
			parenDepth--
		}
		if strings.ContainsRune(";|&\n()", rune(c)) && !(i > 0 && command[i-1] == '>') && !(c == '&' && i+1 < len(command) && command[i+1] == '>') {
			parts = append(parts, command[start:i])
			start = i + 1
			contentStart = start
		}
	}
	return append(parts, command[start:]), patternClosers
}

func hookCommandTargets(command string, dirs []string, reader *shellReader, depth int, inheritedGlob bool) []string {
	return hookCommandTargetsMode(command, dirs, reader, depth, inheritedGlob, false, false)
}

func hookCommandTargetsMode(command string, dirs []string, reader *shellReader, depth int, inheritedGlob, powerShell, strictPOSIX bool) []string {
	if depth > maxShellNesting || !reader.spend(len(command), 0) {
		reader.tooDeep = true
		return nil
	}
	command = hookMaskComments(command, powerShell || !strictPOSIX, !powerShell && !strictPOSIX)
	var targets []string
	if hookHasBackslash(command) {
		targets = append(targets, hookCommandTargetsMode(hookPowerShellPaths(command), dirs, reader, depth, inheritedGlob, powerShell, strictPOSIX)...)
	}
	plainGlob := inheritedGlob || hookDotglob(command) || strings.Contains(command, "GLOBIGNORE")
	command = readHeredocBodies(command, func(body string, quoted bool, header string) {
		shell := false
		interpreter := false
		for _, segment := range hookSegments(header) {
			w := hookUnwrap(posixWords(segment), reader)
			if len(w) > 0 && shellPrograms[programName(w[0])] {
				shell = true
			}
			if hookStdinInterpreter(w) {
				interpreter = true
			}
		}
		if shell {
			targets = append(targets, hookCommandTargets(body, dirs, reader, depth+1, plainGlob)...)
		} else if interpreter {
			targets = append(targets, hookLiteralTargets(body, dirs)...)
		} else if !quoted {
			for _, payload := range hookSubstitutions(strings.ReplaceAll(body, "'", " ")) {
				targets = append(targets, hookCommandTargets(payload, dirs, reader, depth+1, plainGlob)...)
			}
		}
	})
	command = hookWithoutArithmetic(command)
	current := hookCopyDirs(dirs, reader)
	var stack [][]string
	var alternatives []string
	type scope struct {
		current, alternatives []string
		stack                 [][]string
	}
	var scopes []scope
	offset := 0
	segments, patternClosers := hookSegmentsWithScopes(command)
	for _, segment := range segments {
		// Restore failure alternatives when an AND list ends. Subshell directory
		// and pushd state belong to that subshell alone.
		if offset > 0 {
			separator := command[offset-1]
			if strings.ContainsRune(";\n|)", rune(separator)) {
				current = hookUnionDirs(current, alternatives, reader, false)
				alternatives = nil
			}
			if separator == '(' {
				scopes = append(scopes, scope{hookCopyDirs(current, reader), alternatives, hookCopyStack(stack, reader)})
				alternatives = nil
			}
			if separator == ')' && !patternClosers[offset-1] && len(scopes) > 0 {
				saved := scopes[len(scopes)-1]
				scopes = scopes[:len(scopes)-1]
				current, alternatives, stack = saved.current, saved.alternatives, saved.stack
			}
		}
		if reader.incomplete() != "" {
			return targets
		}
		// A successful && transition narrows only this AND list.
		end := offset + len(segment)
		successful := end+1 < len(command) && command[end:end+2] == "&&"
		offset = end + 1
		// Expose redirection operators without touching operators inside quoted scripts.
		var spaced strings.Builder
		var quote byte
		for i := 0; i < len(segment); i++ {
			c := segment[i]
			if c == '\\' && i+1 < len(segment) {
				spaced.WriteByte(c)
				i++
				spaced.WriteByte(segment[i])
				continue
			}
			if quote != 0 {
				spaced.WriteByte(c)
				if c == quote {
					quote = 0
				}
				continue
			}
			if c == '\'' || c == '"' {
				quote = c
			}
			if c == '&' && i+1 < len(segment) && segment[i+1] == '>' {
				continue
			}
			if c == '>' || c == '<' {
				spaced.WriteByte(' ')
				spaced.WriteByte(c)
				if c == '>' {
					for i+1 < len(segment) && strings.ContainsRune(">|&", rune(segment[i+1])) {
						i++
					}
				}
				spaced.WriteByte(' ')
			} else {
				spaced.WriteByte(c)
			}
		}
		words := posixWords(spaced.String())
		posix := words
		nestedWindows := powerShell || hookHasBackslash(segment)
		for _, w := range words {
			switch programName(w) {
			case "powershell", "pwsh", "cmd", "del", "copy", "move", "erase", "ren", "xcopy", "set-content", "remove-item", "add-content", "clear-content", "new-item", "copy-item", "move-item", "rename-item", "set-item", "out-file":
				nestedWindows = true
			}
		}
		windows := nestedWindows && !strictPOSIX
		if windows {
			words, _, _ = powerShellRead(spaced.String(), false)
			if len(words) > 0 && programName(words[0]) == "cmd" {
				words, _ = cmdRead(spaced.String())
			}
		}

		words = hookUnwrap(words, reader)
		if len(words) == 0 {
			continue
		}
		for _, payload := range reader.commandPayloads(posix) {
			targets = append(targets, hookCommandTargetsMode(payload, current, reader, depth+1, plainGlob || nestedWindows, nestedWindows, false)...)
		}
		if windows {
			for _, payload := range reader.commandPayloads(words) {
				targets = append(targets, hookCommandTargetsMode(payload, current, reader, depth+1, plainGlob || nestedWindows, nestedWindows, false)...)
			}
		}
		for _, payload := range hookSubstitutions(segment) {
			targets = append(targets, hookCommandTargetsMode(payload, current, reader, depth+1, plainGlob || nestedWindows, nestedWindows, false)...)
		}
		name := programName(words[0])
		aliases := map[string]string{"ri": "remove-item", "rd": "rmdir", "cpi": "copy-item", "mi": "move-item", "rni": "rename-item", "sc": "set-content", "ac": "add-content", "ni": "new-item", "md": "mkdir"}
		if alias := aliases[name]; alias != "" {
			name = alias
		}
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(segment)), "[io.file]::") || strings.HasPrefix(strings.ToLower(strings.TrimSpace(segment)), "[system.io.file]::") {
			method := strings.ToLower(strings.SplitN(segment, "::", 2)[1])
			if strings.HasPrefix(method, "write") || strings.HasPrefix(method, "delete(") || strings.HasPrefix(method, "move(") || strings.HasPrefix(method, "copy(") {
				targets = append(targets, hookLiteralTargets(segment, current)...)
			}
		}
		directoryWrite := false
		switch name {
		case "rm", "rmdir", "unlink", "mv", "move", "ren", "rename", "del", "erase", "remove-item", "rename-item", "move-item", "cp", "copy", "copy-item", "xcopy", "robocopy", "ln", "install", "rsync":
			directoryWrite = true
		}
		if name == "git" {
			for _, w := range words[1:] {
				if strings.HasPrefix(w, "-") {
					continue
				}
				switch w {
				case "checkout", "restore", "clean", "rm", "mv", "reset", "switch":
					directoryWrite = true
				}
				break
			}
		}

		add := func(word string) {
			word = normalizePathSeparators(word)
			if k := strings.IndexByte(word, '='); k >= 0 {
				word = word[k+1:]
			}
			for _, dir := range current {
				if dir == hookUnknownDir {
					if hookUnknownRelative(word) {
						target := "\x00u" + word
						if directoryWrite {
							target = "\x00d" + target
						}
						if windows || plainGlob {
							target = "\x00w" + target
						}
						targets = append(targets, target)
						continue
					}
					dir = ""
				}
				target := joinCwd(hookExpandPath(word, dir), dir)
				if strings.ContainsAny(target, "*?[{") {
					target = filepath.Clean(target)
				}
				if directoryWrite {
					target = "\x00d" + target
				}
				if windows || plainGlob {
					target = "\x00w" + target
				}
				targets = append(targets, target)
			}
		}
		directoryTarget := hookDirectoryTarget(name, words)
		if directoryTarget {
			old := directoryWrite
			directoryWrite = true
			for i, w := range words {
				if (w == "-C" || w == "-d") && i+1 < len(words) {
					add(words[i+1])
				}
			}
			directoryWrite = old
		}
		if name == "cd" || name == "pushd" || name == "set-location" || name == "popd" {
			if name == "popd" {
				if len(stack) > 0 {
					current = stack[len(stack)-1]
					stack = stack[:len(stack)-1]
				}
				continue
			}
			if name == "pushd" {
				stack = append(stack, hookCopyDirs(current, reader))
			}
			operand := ""
			for i := 1; i < len(words); i++ {
				w := words[i]
				if i+1 < len(words) && (words[i+1] == ">" || words[i+1] == "<") && strings.Trim(w, "0123456789") == "" {
					i++
					if i+1 < len(words) {
						i++
					}
					continue
				}
				if w == ">" || w == "<" {
					if i+1 < len(words) {
						i++
					}
					continue
				}
				if w == "-" || !strings.HasPrefix(w, "-") {
					operand = w
					break
				}
			}
			if operand == "-" {
				continue
			} // Every previously reachable directory remains in current.

			if operand != "" {
				next := hookCopyDirs(current, reader)
				if successful {
					alternatives = hookUnionDirs(alternatives, current, reader, true)
					next = nil
				}
				for _, dir := range current {
					if dir == hookUnknownDir {
						next = []string{hookUnknownDir}
						break
					}
					candidate := filepath.Clean(joinCwd(hookExpandPath(operand, dir), dir))
					if !reader.spend(len(candidate)+len(next)+1, 1) {
						return targets
					}
					found := false
					for _, old := range next {
						if old == candidate {
							found = true
						}
					}
					if !found {
						next = append(next, candidate)
					}
				}
				if len(next) > maxHookDirs {
					next = []string{hookUnknownDir}
				}
				current = next
				if strings.ContainsAny(operand, "*?[{") {
					directoryWrite = true
					add(operand)
				}
			}
			continue
		}
		switch name {
		case "python", "python3", "node", "perl", "ruby", "php", "deno":
			for i, w := range words {
				if (w == "-c" || w == "-e" || w == "--eval" || (name == "php" && w == "-r")) && i+1 < len(words) {
					for _, literal := range strings.FieldsFunc(words[i+1], func(r rune) bool { return strings.ContainsRune("\"'() ,;=+{}<>", r) }) {
						add(literal)
					}
				}
			}
		}
		var operands []string
		inplace := false
		for i := 1; i < len(words); i++ {
			word := words[i]
			if word == ">" {
				for i+1 < len(words) && words[i+1] == ">" {
					i++
				}
				if i+1 < len(words) {
					i++
					add(words[i])
				}
				continue
			}
			if word == "<" {
				if i+1 < len(words) {
					i++
				}
				continue
			}
			if word == "-o" || word == "-O" || word == "--output" {
				if i+1 < len(words) && words[i+1] != ">" && words[i+1] != "<" {
					i++
					add(words[i])
				}
				continue
			}
			if strings.HasPrefix(word, "--") && strings.Contains(word, "=") {
				add(word)
				continue
			}
			if word == "--in-place" || strings.HasPrefix(word, "--in-place=") || word == "-i" || ((name == "sed" || name == "perl") && strings.HasPrefix(word, "-i")) {
				inplace = true
			}
			if !strings.HasPrefix(word, "-") {
				operands = append(operands, word)
			}
		}
		readerCommand := false
		switch name {
		case "expr", "tree", "du", "md5sum", "sha256sum", "sha1sum", "cksum", "bat", "code", "cat", "head", "tail", "less", "more", "ls", "stat", "file", "wc", "grep", "rg", "diff", "cmp", "get-content", "type", "findstr":
			readerCommand = true
		case "find":
			readerCommand = true
			for _, w := range words {
				if w == "-delete" || w == "-exec" || w == "-execdir" || strings.HasPrefix(w, "-fprint") || w == "-fls" {
					readerCommand = false
					directoryWrite = true
				}
			}
		case "python", "python3":
			readerCommand = len(words) > 2 && words[1] == "-m" && words[2] == "json.tool"
			if readerCommand {
				var files []string
				for i := 3; i < len(words); i++ {
					w := words[i]
					if w == "--indent" {
						i++
						continue
					}
					if w == ">" || w == "<" {
						i++
						continue
					}
					if !strings.HasPrefix(w, "-") {
						files = append(files, w)
					}
				}
				if len(files) >= 2 {
					add(files[len(files)-1])
				}
			}
		case "jq", "yq", "sed":
			readerCommand = !inplace
		case "awk", "gawk":
			readerCommand = true
			if len(operands) > 0 {
				script := strings.NewReplacer("{", " ", "}", " ").Replace(operands[0])
				targets = append(targets, hookCommandTargets(script, current, reader, depth+1, plainGlob || windows)...)
			}
		case "git":
			if len(operands) > 0 {
				switch strings.ToLower(operands[0]) {
				case "diff", "log", "show", "status", "blame", "ls-files", "grep", "add":
					readerCommand = true
				}
			}
			if len(operands) > 0 && operands[0] == "rm" {
				for _, w := range words {
					if w == "--cached" {
						readerCommand = true
					}
				}
			}
		case "cp", "copy", "copy-item", "xcopy", "robocopy", "ln", "install", "rsync":
			if name == "ln" {
				for _, word := range operands {
					if strings.ContainsAny(word, "*?[{") {
						add(word)
					}
				}
			}
			readerCommand = true
			targetDirectory := false
			for _, word := range words {
				if word == "-t" || word == "--target-directory" || strings.HasPrefix(word, "--target-directory=") {
					targetDirectory = true
				}
			}
			if !targetDirectory && len(operands) > 0 {
				add(operands[len(operands)-1])
			}
			for i, word := range words {
				if (word == "-t" || word == "--target-directory") && i+1 < len(words) {
					add(words[i+1])
				}
				if strings.HasPrefix(word, "--target-directory=") {
					add(strings.TrimPrefix(word, "--target-directory="))
				}
			}
		}
		if !readerCommand {
			for _, word := range operands {
				add(word)
			}
		}
	}
	return targets
}

// Arithmetic operands are not pathname expansions. Preserve nested command
// substitutions for their separate recursive analysis before dropping the expression.
func hookWithoutArithmetic(command string) string {
	var out strings.Builder
	for i := 0; i < len(command); {
		if command[i] == '\'' || command[i] == '"' {
			quote := command[i]
			start := i
			i++
			for i < len(command) {
				if command[i] == '\\' && quote != '\'' && i+1 < len(command) {
					i += 2
					continue
				}
				if command[i] == quote {
					i++
					break
				}
				i++
			}
			out.WriteString(command[start:i])
			continue
		}
		if command[i] == '\\' && i+1 < len(command) {
			out.WriteString(command[i : i+2])
			i += 2
			continue
		}
		if strings.HasPrefix(command[i:], "$((") || strings.HasPrefix(command[i:], "((") {
			start := i
			if command[i] == '$' {
				i++
			}
			i += 2
			nesting := 2
			for i < len(command) && nesting > 0 {
				if command[i] == '(' {
					nesting++
				}
				if command[i] == ')' {
					nesting--
				}
				i++
			}
			for _, payload := range commandSubstitutions(command[start:i]) {
				if strings.HasPrefix(payload, "(") && command[start] == '$' {
					for _, nested := range commandSubstitutions(payload) {
						out.WriteString(" ; ")
						out.WriteString(nested)
						out.WriteString(" ; ")
					}
				} else {
					out.WriteString(" ; ")
					out.WriteString(payload)
					out.WriteString(" ; ")
				}
			}
			out.WriteByte(' ')
		} else {
			out.WriteByte(command[i])
			i++
		}
	}
	return out.String()
}

// The outer payload of $((...)) is arithmetic, but substitutions nested in it execute.
func hookSubstitutions(command string) []string {
	var payloads []string
	for _, payload := range commandSubstitutions(command) {
		if strings.HasPrefix(payload, "(") && strings.HasSuffix(payload, ")") {
			payloads = append(payloads, commandSubstitutions(payload)...)
		} else {
			payloads = append(payloads, payload)
		}
	}
	return payloads
}

const maxHookDirs = 32
const hookUnknownDir = "\x00unknown-cwd"

func hookCopyDirs(dirs []string, reader *shellReader) []string {
	for _, dir := range dirs {
		if !reader.spend(len(dir)+1, 1) {
			return nil
		}
	}
	return append([]string{}, dirs...)
}

// AND failure alternatives have a hard cap; ordinary cwd saturation retains
// uncertainty without rejecting unrelated build commands.
func hookUnionDirs(a, b []string, reader *shellReader, failureAlternatives bool) []string {
	out := hookCopyDirs(a, reader)
	for _, dir := range b {
		if !reader.spend(len(dir)+len(out)+1, 1) {
			return nil
		}
		if dir == hookUnknownDir || (len(out) > 0 && out[0] == hookUnknownDir) {
			return []string{hookUnknownDir}
		}
		found := false
		for _, old := range out {
			if old == dir {
				found = true
				break
			}
		}
		if !found {
			if len(out) == maxHookDirs {
				if failureAlternatives {
					reader.tooDeep = true
					return nil
				}
				return []string{hookUnknownDir}
			}
			out = append(out, dir)
		}
	}
	return out
}

// Mask comments without changing offsets used by the segment/scope reader.
// hookMaskComments blanks shell comments so their text cannot open a quote that
// hides later commands. unknownShell means the text may run under bash or
// PowerShell: then only text that is a comment in the reading chosen for each
// backtick is masked, and the choice is made so it never masks text either shell
// would run outside that span.
func hookMaskComments(command string, powerShell, unknownShell bool) string {
	out := []byte(command)
	// ansi marks a $'...' string, where a backslash escapes the next byte,
	// including a single quote, unlike a plain '...' string.
	var quote byte
	ansi := false
	for i := 0; i < len(command); i++ {
		c := command[i]
		if c == '\\' && (quote != '\'' || ansi) {
			i++
			continue
		}
		if c == '`' && quote == 0 {
			// POSIX: a backtick opens a command substitution, read like a quoted
			// span. PowerShell: it escapes the next byte. For an unknown shell, a
			// backtick with a partner later on the same line is read as a span.
			partner := strings.IndexByte(command[i+1:], '`')
			newline := strings.IndexByte(command[i+1:], '\n')
			span := !powerShell || (unknownShell && partner >= 0 && (newline < 0 || partner < newline))
			if span {
				quote = '`'
			} else {
				i++
			}
			continue
		}
		if powerShell && !unknownShell && c == '`' && quote == '"' {
			i++ // PowerShell escape inside a double-quoted string.
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
				ansi = false
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			ansi = c == '\'' && i > 0 && command[i-1] == '$'
			continue
		}
		end := i
		if powerShell && strings.HasPrefix(command[i:], "<#") {
			if k := strings.Index(command[i+2:], "#>"); k >= 0 {
				end = i + 2 + k + 2
			} else {
				end = len(command)
			}
		} else if c == '#' && commentMayStart(command, i) {
			for end < len(command) && command[end] != '\n' {
				end++
			}
		}
		if end > i {
			for j := i; j < end; j++ {
				if out[j] != '\n' {
					out[j] = ' '
				}
			}
			i = end - 1
		}
	}
	return string(out)
}

func hookCopyStack(stack [][]string, reader *shellReader) [][]string {
	if !reader.spend(0, len(stack)) {
		return nil
	}
	// Entries are immutable: directory changes always allocate a new set.
	return append([][]string{}, stack...)
}
