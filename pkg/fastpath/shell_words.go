package fastpath

import (
	"strconv"
	"strings"
)

// maxShellNesting bounds how deep strings that a program will run are read as commands.
const maxShellNesting = 3

// shellWords lists what a command's words may mean, for the transcript guard. The shell
// that will run the command is unknown and the shells disagree: a backslash escapes in POSIX
// shells and separates paths on Windows, while PowerShell escapes with a backtick and cmd.exe
// with a caret. So the command is read under each set of rules and all results are kept. This
// is deliberately not a shell parser: it adds spellings and never decides between them.
// Quoted text stays text unless a recognized program will run it (see commandPayloads) or it
// is a substitution. It cannot see variables, globs, brace expansion, or anything else the
// shell computes.
func shellWords(command string) []string {
	return readCommand(command, false)
}

// shellTextWords is shellWords without heredoc bodies, which are data unless a shell reads them.
// Only the spelled-out-name rule uses it: path resolution still sees those words, so a
// heredoc that a shell runs, or a marker misread as a heredoc, cannot hide a real path.
func shellTextWords(command string) []string {
	return readCommand(command, true)
}

func readCommand(command string, skipHeredocs bool) []string {
	seen := map[string]bool{}
	nested := map[string]bool{}
	var words []string
	var visit func(text string, depth int)
	visit = func(text string, depth int) {
		if skipHeredocs {
			text = stripHeredocBodies(text)
		}
		nest := func(payload string) {
			if depth < maxShellNesting && !nested[payload] {
				nested[payload] = true
				visit(payload, depth+1)
			}
		}
		readings := [][]string{posixWords(text), powerShellWords(text), cmdWords(text), strings.Fields(text)}
		// An apostrophe is not a quote in cmd.exe, so a word holding one came from text that
		// the other shells read as quoted. Its quotes would be removed wrongly here.
		kept := readings[2][:0]
		for _, word := range readings[2] {
			if !strings.Contains(word, "'") {
				kept = append(kept, word)
			}
		}
		readings[2] = kept
		for _, reading := range readings {
			for _, word := range reading {
				for _, form := range wordForms(word) {
					if !seen[form] {
						seen[form] = true
						words = append(words, form)
					}
				}
			}
			for _, payload := range commandPayloads(reading) {
				nest(payload)
			}
		}
		for _, substitution := range commandSubstitutions(text) {
			nest(substitution)
		}
	}
	visit(command, 0)
	return words
}

// shellPrograms take a command string after a flag holding a "c", such as -c or -lc.
var shellPrograms = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "mksh": true, "ash": true, "fish": true, "su": true}

// interpreterFlags are the flags that make an interpreter run a string from the command line.
var interpreterFlags = map[string][]string{
	"python": {"-c"}, "pypy": {"-c"}, "node": {"-e", "--eval", "-p", "--print"}, "nodejs": {"-e", "--eval", "-p", "--print"},
	"bun": {"-e", "--eval"}, "perl": {"-e", "-E", "-ne", "-pe"}, "ruby": {"-e", "-ne", "-pe"}, "php": {"-r"}, "lua": {"-e"},
}

// commandPayloads returns the strings in a command's words that a recognized program will run.
func commandPayloads(words []string) []string {
	var payloads []string
	for i, word := range words {
		name := programName(word)
		rest := words[i+1:]
		switch {
		case name == "eval":
			payloads = append(payloads, strings.Join(rest, " "))
		case shellPrograms[name]:
			for j, flag := range rest {
				if value, ok := strings.CutPrefix(flag, "--command="); ok {
					payloads = append(payloads, value)
					break
				}
				isFlag := flag == "--command" || (len(flag) > 1 && flag[0] == '-' && flag[1] != '-' && strings.Contains(flag, "c"))
				if isFlag && j+1 < len(rest) {
					payloads = append(payloads, rest[j+1])
					break
				}
			}
		case name == "cmd":
			for j, flag := range rest {
				lower := strings.ToLower(flag)
				if len(lower) >= 2 && lower[0] == '/' && strings.IndexByte("ckr", lower[1]) >= 0 {
					payloads = append(payloads, strings.TrimSpace(flag[2:]+" "+strings.Join(rest[j+1:], " ")))
					break
				}
			}
		case name == "powershell" || name == "pwsh":
			// PowerShell runs its arguments as a command, with or without -Command.
			for j, flag := range rest {
				lower := strings.ToLower(flag)
				if len(lower) >= 2 && (lower[0] == '-' || lower[0] == '/') && strings.HasPrefix("command", lower[1:]) {
					rest = rest[j+1:]
					break
				}
			}
			payloads = append(payloads, strings.Join(rest, " "))
		default:
			for _, known := range interpreterFlags[interpreterName(name)] {
				for j, flag := range rest {
					if flag == known && j+1 < len(rest) {
						payloads = append(payloads, rest[j+1])
					}
				}
			}
		}
	}
	return payloads
}

// programName reduces /usr/bin/Python3.exe to python3.
func programName(word string) string {
	if i := strings.LastIndexAny(word, `/\`); i >= 0 {
		word = word[i+1:]
	}
	return strings.TrimSuffix(strings.ToLower(word), ".exe")
}

// interpreterName reduces versioned names such as python3.11 to python.
func interpreterName(name string) string {
	return strings.TrimRight(name, "0123456789.")
}

// commandSubstitutions returns the outermost $(...) and `...` spans a POSIX shell would run,
// in one pass. Single-quoted text is literal, so it is skipped.
func commandSubstitutions(s string) []string {
	var spans []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\':
			i++
		case c == '\'' && depth == 0:
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				return spans
			}
			i += end + 1
		case c == '`' && depth == 0:
			end := i + 1
			for end < len(s) && s[end] != '`' {
				if s[end] == '\\' {
					end++
				}
				end++
			}
			if end >= len(s) {
				return append(spans, s[i+1:])
			}
			spans = append(spans, s[i+1:end])
			i = end
		case c == '$' && i+1 < len(s) && s[i+1] == '(':
			if depth == 0 {
				start = i + 2
			}
			depth++
			i++
		case c == '(' && depth > 0:
			depth++
		case c == ')' && depth > 0:
			depth--
			if depth == 0 {
				spans = append(spans, s[start:i])
			}
		}
	}
	if depth > 0 {
		spans = append(spans, s[start:])
	}
	return spans
}

// stripHeredocBodies removes heredoc bodies the way a POSIX shell finds them. It tracks quotes
// and comments, because a marker inside either one is not a heredoc and the lines after it
// are commands. Unterminated bodies run to the end of the text, as in a shell.
func stripHeredocBodies(s string) string {
	if !strings.Contains(s, "<<") {
		return s
	}
	type heredoc struct {
		delimiter string
		tabs      bool
	}
	var out strings.Builder
	var pending []heredoc
	atWordStart := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\':
			end := min(i+2, len(s))
			out.WriteString(s[i:end])
			i = end - 1
			atWordStart = false
		case c == '\'':
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				out.WriteString(s[i:])
				return out.String()
			}
			out.WriteString(s[i : i+end+2])
			i += end + 1
			atWordStart = false
		case c == '"':
			end := i + 1
			for end < len(s) && s[end] != '"' {
				if s[end] == '\\' {
					end++
				}
				end++
			}
			if end >= len(s) {
				out.WriteString(s[i:])
				return out.String()
			}
			out.WriteString(s[i : end+1])
			i = end
			atWordStart = false
		case c == '#' && atWordStart:
			end := strings.IndexByte(s[i:], '\n')
			if end < 0 {
				out.WriteString(s[i:])
				return out.String()
			}
			out.WriteString(s[i : i+end])
			i += end - 1
		case strings.HasPrefix(s[i:], "$(("):
			end := strings.Index(s[i:], "))")
			if end < 0 {
				out.WriteString(s[i:])
				return out.String()
			}
			out.WriteString(s[i : i+end+2])
			i += end + 1
			atWordStart = false
		case strings.HasPrefix(s[i:], "<<<"):
			out.WriteString("<<<")
			i += 2
			atWordStart = false
		case strings.HasPrefix(s[i:], "<<"):
			j := i + 2
			tabs := j < len(s) && s[j] == '-'
			if tabs {
				j++
			}
			for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
				j++
			}
			end := j
			for end < len(s) && !isShellSpace(s[end]) && strings.IndexByte(";&|<>()", s[end]) < 0 {
				end++
			}
			if words := posixWords(s[j:end]); len(words) == 1 && words[0] != "" {
				pending = append(pending, heredoc{delimiter: words[0], tabs: tabs})
			}
			out.WriteString(s[i:end])
			i = end - 1
			atWordStart = false
		case c == '\n':
			out.WriteByte(c)
			atWordStart = true
			for _, doc := range pending {
				for i+1 < len(s) {
					lineEnd := strings.IndexByte(s[i+1:], '\n')
					line := s[i+1:]
					next := len(s) - 1
					if lineEnd >= 0 {
						line = s[i+1 : i+1+lineEnd]
						next = i + 1 + lineEnd
					}
					i = next
					if doc.tabs {
						line = strings.TrimLeft(line, "\t")
					}
					if line == doc.delimiter {
						break
					}
				}
			}
			pending = nil
		default:
			out.WriteByte(c)
			atWordStart = isShellSpace(c) || strings.IndexByte(";&|(", c) >= 0
		}
	}
	return out.String()
}

// wordForms returns a word and the paths it may carry: parts split at operators and
// separators, and values attached to a short flag or an @.
func wordForms(word string) []string {
	forms := []string{word}
	add := func(parts []string) {
		if len(parts) > 1 || (len(parts) == 1 && parts[0] != word) {
			forms = append(forms, parts...)
		}
	}
	// Operators first, so a drive-letter path after one (x>>C:/a) survives whole. Splitting at
	// colons is a second pass, because a colon is also part of that path.
	operatorParts := strings.FieldsFunc(word, func(r rune) bool { return strings.ContainsRune(";|&<>()`=,", r) })
	add(operatorParts)
	for _, part := range operatorParts {
		if colonParts := strings.Split(part, ":"); len(colonParts) > 1 {
			forms = append(forms, colonParts...)
		}
	}
	for _, form := range append([]string(nil), forms...) {
		if len(form) > 2 && form[0] == '-' && form[1] != '-' {
			forms = append(forms, form[2:])
		}
		if len(form) > 1 && form[0] == '@' {
			forms = append(forms, form[1:])
		}
	}
	return forms
}

func isShellSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// wordBuilder collects words, keeping an empty quoted word distinct from no word.
type wordBuilder struct {
	words   []string
	current strings.Builder
	started bool
}

func (b *wordBuilder) writeByte(c byte) {
	b.current.WriteByte(c)
	b.started = true
}

func (b *wordBuilder) writeString(s string) {
	b.current.WriteString(s)
	b.started = true
}

func (b *wordBuilder) flush() {
	if b.started {
		b.words = append(b.words, b.current.String())
		b.current.Reset()
		b.started = false
	}
}

// posixWords splits like sh and bash: backslash escapes, single and double quotes, adjacent
// segments, line continuations, and the $'...' and $"..." forms.
func posixWords(s string) []string {
	var b wordBuilder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case isShellSpace(c):
			b.flush()
		case c == '\\':
			i++
			if i < len(s) && s[i] != '\n' {
				b.writeByte(s[i])
			}
		case c == '\'':
			b.started = true
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				b.writeString(s[i+1:])
				i = len(s)
				break
			}
			b.writeString(s[i+1 : i+1+end])
			i += end + 1
		case c == '$' && i+1 < len(s) && s[i+1] == '\'':
			decoded, next := ansiQuoted(s, i+2)
			b.writeString(decoded)
			i = next
		case c == '"' || (c == '$' && i+1 < len(s) && s[i+1] == '"'):
			if c == '$' {
				i++
			}
			b.started = true
			for i++; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' && i+1 < len(s) && strings.IndexByte("$`\"\\\n", s[i+1]) >= 0 {
					i++
					if s[i] == '\n' {
						continue
					}
				}
				b.writeByte(s[i])
			}
		default:
			b.writeByte(c)
		}
	}
	b.flush()
	return b.words
}

var ansiEscapes = map[byte]byte{'a': 7, 'b': 8, 'e': 27, 'E': 27, 'f': 12, 'n': 10, 'r': 13, 't': 9, 'v': 11, '\\': '\\', '\'': '\'', '"': '"', '?': '?'}

// ansiQuoted decodes the body of $'...' starting at i, returning it and the closing quote's index.
func ansiQuoted(s string, i int) (string, int) {
	var out strings.Builder
	for ; i < len(s) && s[i] != '\''; i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			out.WriteByte(s[i])
			continue
		}
		i++
		c := s[i]
		if value, ok := ansiEscapes[c]; ok {
			out.WriteByte(value)
			continue
		}
		switch {
		case c == 'x':
			value, used := parseDigits(s[i+1:], 16, 2)
			if used == 0 {
				out.WriteString(`\x`)
				continue
			}
			out.WriteByte(byte(value))
			i += used
		case c == 'u' || c == 'U':
			width := 4
			if c == 'U' {
				width = 8
			}
			value, used := parseDigits(s[i+1:], 16, width)
			if used == 0 {
				out.WriteByte('\\')
				out.WriteByte(c)
				continue
			}
			out.WriteRune(rune(value))
			i += used
		case c >= '0' && c <= '7':
			value, used := parseDigits(s[i:], 8, 3)
			out.WriteByte(byte(value))
			i += used - 1
		case c == 'c' && i+1 < len(s):
			i++
			out.WriteByte(s[i] & 0x1f)
		default:
			out.WriteByte('\\')
			out.WriteByte(c)
		}
	}
	return out.String(), i
}

// parseDigits reads up to width digits of a base, returning the value and the count read.
func parseDigits(s string, base, width int) (uint64, int) {
	used := 0
	for used < len(s) && used < width {
		if _, err := strconv.ParseUint(s[used:used+1], base, 8); err != nil {
			break
		}
		used++
	}
	if used == 0 {
		return 0, 0
	}
	value, err := strconv.ParseUint(s[:used], base, 64)
	if err != nil {
		return 0, 0
	}
	return value, used
}

// powerShellWords splits like PowerShell: a backtick escapes outside single quotes, a doubled
// quote is a literal quote, and a backslash is an ordinary character. The escape is read as
// removing the backtick, so control escapes such as `n give the plain letter.
func powerShellWords(s string) []string {
	var b wordBuilder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case isShellSpace(c):
			b.flush()
		case c == '`':
			i++
			if i < len(s) {
				b.writeByte(s[i])
			}
		case c == '\'':
			b.started = true
			for i++; i < len(s); i++ {
				if s[i] == '\'' {
					if i+1 < len(s) && s[i+1] == '\'' {
						i++
					} else {
						break
					}
				}
				b.writeByte(s[i])
			}
		case c == '"':
			b.started = true
			for i++; i < len(s); i++ {
				if s[i] == '`' && i+1 < len(s) {
					i++
				} else if s[i] == '"' {
					if i+1 < len(s) && s[i+1] == '"' {
						i++
					} else {
						break
					}
				}
				b.writeByte(s[i])
			}
		default:
			b.writeByte(c)
		}
	}
	b.flush()
	return b.words
}

// cmdWords splits like cmd.exe: a caret escapes outside double quotes, and a backslash is ordinary.
func cmdWords(s string) []string {
	var b wordBuilder
	inQuotes := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQuotes = !inQuotes
			b.started = true
		case inQuotes:
			b.writeByte(c)
		case isShellSpace(c):
			b.flush()
		case c == '^':
			i++
			if i < len(s) {
				b.writeByte(s[i])
			}
		default:
			b.writeByte(c)
		}
	}
	b.flush()
	return b.words
}
