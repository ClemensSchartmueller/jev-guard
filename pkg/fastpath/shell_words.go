package fastpath

import (
	"strconv"
	"strings"
)

// maxShellNesting bounds how deep strings that a program will run are read as commands.
const maxShellNesting = 3

// The shell reader's cumulative work budget for one tool call, across every command, reading
// and nested payload. It is checked before text is read, copied or recursed into, so hostile
// input such as "eval eval eval ..." (each eval runs the rest of the line) stops early instead
// of growing with the square or cube of its length. A reader over budget stops reading; its
// caller reports the call as too large to check, never as clean.
const (
	maxShellReadBytes = 16 * maxGuardCommandBytes // text read and payload text copied
	maxShellTokens    = 8 << 20                   // words, word forms and scan steps
	maxShellPayloads  = 4096                      // nested commands read
)

// shellReader reads commands under one work budget. The zero value is not ready; use
// newShellReader.
type shellReader struct {
	bytes, tokens, payloads int
	exhausted               bool
	// tooDeep is set when a command a program will run was not read because it is nested
	// deeper than maxShellNesting. Reading goes on, so a protected name found elsewhere is
	// still reported, but the caller must not report the call as clean.
	tooDeep bool
	// expands holds the words (and word forms) holding a $ or % that some shell would expand:
	// one that was not single-quoted or escaped (see wordBuilder.expands). Only these words get
	// the hook's environment variables filled in, so '$X/state' stays the literal name it is.
	expands map[string]bool
}

func newShellReader() *shellReader { return &shellReader{expands: map[string]bool{}} }

// incomplete reports why part of what the reader was given was not read, or "" when all of it was.
func (r *shellReader) incomplete() string {
	switch {
	case r.exhausted:
		return "a command needs more work to read than the check will do"
	case r.tooDeep:
		return "a command nests commands a program will run deeper than the check will read"
	}
	return ""
}

// spend charges work to the budget and reports whether it is still within it.
func (r *shellReader) spend(bytes, tokens int) bool {
	if r.exhausted {
		return false
	}
	r.bytes += bytes
	r.tokens += tokens
	if r.bytes > maxShellReadBytes || r.tokens > maxShellTokens {
		r.exhausted = true
	}
	return !r.exhausted
}

// spendPayload charges one nested command of the given size before it is built.
func (r *shellReader) spendPayload(size int) bool {
	r.payloads++
	if r.payloads > maxShellPayloads {
		r.exhausted = true
	}
	return r.spend(size, 1)
}

// shellWords lists what a command's words may mean. The shell that will run the command is
// unknown and the shells disagree: a backslash escapes in POSIX shells and separates paths on
// Windows, while PowerShell escapes with a backtick and cmd.exe with a caret. So the command is
// read under each set of rules and all results are kept. This is deliberately not a shell
// parser: it adds spellings and never decides between them. Quoted text stays text unless a
// recognized program will run it (see commandPayloads) or it is a substitution. It cannot see
// variables or anything else the shell computes; globs and brace expansion are reported
// separately as patterns (see shellReader.read). It reads with a fresh budget; callers that
// must report an exhausted budget use a shellReader.
func shellWords(command string) []string {
	words, _ := newShellReader().read(command, false)
	return words
}

// read returns a command's words (see shellWords) and its glob patterns: the words a POSIX
// shell or PowerShell would expand as a glob or brace pattern because they hold an unquoted
// *, ?, [ or (POSIX only) {. In a pattern, quoted and escaped characters are escaped with a
// backslash, so a quoted '*' stays literal. Reading stops once the budget is spent; check
// r.incomplete. A command a program will run that is nested deeper than maxShellNesting is
// not read and sets r.tooDeep; the rest is still read. With skipHeredocs set, heredoc bodies are left out: they are data unless a shell
// reads them. Only the transcript guard's spelled-out-name rule uses that; path resolution still
// sees those words, so a heredoc that a shell runs, or a marker misread as a heredoc, cannot
// hide a real path.
func (r *shellReader) read(command string, skipHeredocs bool) (words, patterns []string) {
	seen := map[string]bool{}
	seenPatterns := map[string]bool{}
	nested := map[string]bool{}
	var visit func(text string, depth int)
	visit = func(text string, depth int) {
		if !r.spend(len(text), 0) {
			return
		}
		if skipHeredocs {
			text = stripHeredocBodies(text)
		}
		nest := func(payload string) {
			if nested[payload] {
				return
			}
			if depth >= maxShellNesting {
				r.tooDeep = true
				return
			}
			nested[payload] = true
			visit(payload, depth+1)
		}
		posix, posixPatterns, posixExpands := posixRead(text, true)
		ps, psPatterns, psExpands := powerShellRead(text, true)
		cmd, cmdExpands := cmdRead(text)
		fields := strings.Fields(text)
		// Raw text: a $ in it is unquoted unless the word also holds a single quote.
		fieldExpands := make([]bool, len(fields))
		for i, word := range fields {
			fieldExpands[i] = !strings.Contains(word, "'")
		}
		// An apostrophe is not a quote in cmd.exe, so a word holding one came from text that
		// the other shells read as quoted. Its quotes would be removed wrongly here.
		kept, keptExpands := cmd[:0], cmdExpands[:0]
		for i, word := range cmd {
			if !strings.Contains(word, "'") {
				kept = append(kept, word)
				keptExpands = append(keptExpands, cmdExpands[i])
			}
		}
		readings := [][]string{posix, ps, kept, fields}
		expands := [][]bool{posixExpands, psExpands, keptExpands, fieldExpands}
		for _, pattern := range append(posixPatterns, psPatterns...) {
			if !seenPatterns[pattern] {
				seenPatterns[pattern] = true
				patterns = append(patterns, pattern)
			}
		}
		if !r.spend(0, len(posixPatterns)+len(psPatterns)) {
			return
		}
		for n, reading := range readings {
			if !r.spend(0, len(reading)) {
				return
			}
			for k, word := range reading {
				forms := wordForms(word)
				if !r.spend(0, len(forms)) {
					return
				}
				for _, form := range forms {
					if expands[n][k] && strings.ContainsAny(form, "$%") {
						r.expands[form] = true
					}
					if !seen[form] {
						seen[form] = true
						words = append(words, form)
					}
				}
			}
			for _, payload := range r.commandPayloads(reading) {
				nest(payload)
			}
			if r.exhausted {
				return
			}
		}
		for _, substitution := range commandSubstitutions(text) {
			nest(substitution)
		}
	}
	visit(command, 0)
	return words, patterns
}

// shellPrograms take a command string after a flag holding a "c", such as -c or -lc.
var shellPrograms = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "mksh": true, "ash": true, "fish": true, "su": true}

// interpreterFlags are the flags that make an interpreter run a string from the command line.
var interpreterFlags = map[string][]string{
	"python": {"-c"}, "pypy": {"-c"}, "node": {"-e", "--eval", "-p", "--print"}, "nodejs": {"-e", "--eval", "-p", "--print"},
	"bun": {"-e", "--eval"}, "perl": {"-e", "-E", "-ne", "-pe"}, "ruby": {"-e", "-ne", "-pe"}, "php": {"-r"}, "lua": {"-e"},
}

// commandPayloads returns the strings in a command's words that a recognized program will run.
// Every scan and every payload is charged to the budget before it happens; once the budget is
// spent, the payloads found so far are returned.
func (r *shellReader) commandPayloads(words []string) []string {
	var payloads []string
	// suffix[i] is the length of strings.Join(words[i:], " "), so sizes are known before joining.
	var suffix []int
	joinedSize := func(i int) int {
		if suffix == nil {
			suffix = make([]int, len(words)+1)
			for j := len(words) - 1; j >= 0; j-- {
				suffix[j] = suffix[j+1] + len(words[j])
				if j < len(words)-1 {
					suffix[j]++
				}
			}
		}
		return suffix[i]
	}
	add := func(size int, build func() string) bool {
		if !r.spendPayload(size) {
			return false
		}
		payloads = append(payloads, build())
		return true
	}
	for i, word := range words {
		name := programName(word)
		rest := words[i+1:]
		switch {
		case name == "eval":
			if !add(joinedSize(i+1), func() string { return strings.Join(rest, " ") }) {
				return payloads
			}
		case shellPrograms[name]:
			if !r.spend(0, len(rest)) {
				return payloads
			}
			for j, flag := range rest {
				if value, ok := strings.CutPrefix(flag, "--command="); ok {
					if !add(len(value), func() string { return value }) {
						return payloads
					}
					break
				}
				isFlag := flag == "--command" || (len(flag) > 1 && flag[0] == '-' && flag[1] != '-' && strings.Contains(flag, "c"))
				if isFlag && j+1 < len(rest) {
					value := rest[j+1]
					if !add(len(value), func() string { return value }) {
						return payloads
					}
					break
				}
			}
		case name == "cmd":
			if !r.spend(0, len(rest)) {
				return payloads
			}
			for j, flag := range rest {
				lower := strings.ToLower(flag)
				if len(lower) >= 2 && lower[0] == '/' && strings.IndexByte("ckr", lower[1]) >= 0 {
					tail := rest[j+1:]
					if !add(len(flag)+joinedSize(i+j+2), func() string { return strings.TrimSpace(flag[2:] + " " + strings.Join(tail, " ")) }) {
						return payloads
					}
					break
				}
			}
		case name == "powershell" || name == "pwsh":
			if !r.spend(0, len(rest)) {
				return payloads
			}
			// PowerShell runs its arguments as a command, with or without -Command.
			start := i + 1
			for j, flag := range rest {
				lower := strings.ToLower(flag)
				if len(lower) >= 2 && (lower[0] == '-' || lower[0] == '/') && strings.HasPrefix("command", lower[1:]) {
					start = i + j + 2
					break
				}
			}
			tail := words[start:]
			if !add(joinedSize(start), func() string { return strings.Join(tail, " ") }) {
				return payloads
			}
		default:
			flags := interpreterFlags[interpreterName(name)]
			if len(flags) == 0 {
				continue
			}
			if !r.spend(0, len(flags)*len(rest)) {
				return payloads
			}
			for _, known := range flags {
				for j, flag := range rest {
					if flag == known && j+1 < len(rest) {
						value := rest[j+1]
						if !add(len(value), func() string { return value }) {
							return payloads
						}
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

// wordBuilder collects words, keeping an empty quoted word distinct from no word. With track
// set, it also collects the words a shell would expand as glob patterns (see shellReader.read).
type wordBuilder struct {
	words   []string
	current strings.Builder
	started bool
	// expanded[i] is set when words[i] holds a variable reference the shell expands: a $
	// (POSIX, PowerShell) or % (cmd.exe) that was not quoted literally or escaped.
	expanded []bool
	expands  bool

	track    bool // collect patterns
	braces   bool // an unquoted { starts a brace expansion
	patterns []string
	pattern  strings.Builder
	glob     bool
}

// patternMeta are the characters escaped when they are literal in a pattern.
const patternMeta = `*?[]{},\`

// writeByte adds a literal character: one that was quoted or escaped. A literal $ is also
// escaped in a pattern, so that only a variable the shell expands is filled in.
func (b *wordBuilder) writeByte(c byte) {
	b.current.WriteByte(c)
	b.started = true
	if b.track {
		if c == '$' || strings.IndexByte(patternMeta, c) >= 0 {
			b.pattern.WriteByte('\\')
		}
		b.pattern.WriteByte(c)
	}
}

// writeExpanding adds a character that is quoted but where the shell still expands
// variables, as in double quotes. A $ there starts a variable reference.
func (b *wordBuilder) writeExpanding(c byte) {
	if c != '$' {
		b.writeByte(c)
		return
	}
	b.current.WriteByte(c)
	b.started = true
	b.expands = true
	if b.track {
		b.pattern.WriteByte(c)
	}
}

func (b *wordBuilder) writeString(s string) {
	if !b.track {
		b.current.WriteString(s)
		b.started = true
		return
	}
	b.started = true
	for i := 0; i < len(s); i++ {
		b.writeByte(s[i])
	}
}

// writeRaw adds an unquoted character, which the shell may expand as part of a pattern.
func (b *wordBuilder) writeRaw(c byte) {
	b.current.WriteByte(c)
	b.started = true
	if c == '$' {
		b.expands = true
	}
	if b.track {
		b.pattern.WriteByte(c)
		if c == '*' || c == '?' || c == '[' || (b.braces && c == '{') {
			b.glob = true
		}
	}
}

func (b *wordBuilder) flush() {
	if b.started {
		b.words = append(b.words, b.current.String())
		b.expanded = append(b.expanded, b.expands)
		b.current.Reset()
		b.started = false
	}
	b.expands = false
	if b.glob {
		b.patterns = append(b.patterns, b.pattern.String())
	}
	b.pattern.Reset()
	b.glob = false
}

// posixWords splits like sh and bash: backslash escapes, single and double quotes, adjacent
// segments, line continuations, and the $'...' and $"..." forms.
func posixWords(s string) []string {
	words, _, _ := posixRead(s, false)
	return words
}

// posixRead is posixWords that, with track set, also returns the glob and brace patterns. It
// also reports which words hold a variable the shell expands (see wordBuilder.expanded).
func posixRead(s string, track bool) (words, patterns []string, expanded []bool) {
	b := wordBuilder{track: track, braces: true}
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
					b.writeByte(s[i])
					continue
				}
				b.writeExpanding(s[i])
			}
		default:
			b.writeRaw(c)
		}
	}
	b.flush()
	return b.words, b.patterns, b.expanded
}

var ansiEscapes = map[byte]byte{'a': 7, 'b': 8, 'e': 27, 'E': 27, 'f': 12, 'n': 10, 'r': 13, 't': 9, 'v': 11, '\\': '\\', '\'': '\'', '"': '"', '?': '?'}

// ansiQuoted decodes the body of $'...' starting at i, returning it and the closing quote's index.
// Like Bash, it drops the rest of the body after the first decoded NUL (\0, \x00, \u0000,
// \c@): `.jev$'\0x'guard` is the word ".jevguard". Escapes are still read to find the end.
func ansiQuoted(s string, i int) (string, int) {
	var decoded strings.Builder
	out := &nulTruncator{out: &decoded}
	for ; i < len(s) && s[i] != '\''; i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			out.writeByte(s[i])
			continue
		}
		i++
		c := s[i]
		if value, ok := ansiEscapes[c]; ok {
			out.writeByte(value)
			continue
		}
		switch {
		case c == 'x':
			value, used := parseDigits(s[i+1:], 16, 2)
			if used == 0 {
				out.writeString(`\x`)
				continue
			}
			out.writeByte(byte(value))
			i += used
		case c == 'u' || c == 'U':
			width := 4
			if c == 'U' {
				width = 8
			}
			value, used := parseDigits(s[i+1:], 16, width)
			if used == 0 {
				out.writeByte('\\')
				out.writeByte(c)
				continue
			}
			if value == 0 {
				out.truncated = true
			} else {
				out.writeRune(rune(value))
			}
			i += used
		case c >= '0' && c <= '7':
			value, used := parseDigits(s[i:], 8, 3)
			out.writeByte(byte(value))
			i += used - 1
		case c == 'c' && i+1 < len(s):
			i++
			out.writeByte(s[i] & 0x1f)
		default:
			out.writeByte('\\')
			out.writeByte(c)
		}
	}
	return decoded.String(), i
}

// nulTruncator writes to out until a NUL byte is written, then drops everything.
type nulTruncator struct {
	out       *strings.Builder
	truncated bool
}

func (w *nulTruncator) writeByte(c byte) {
	if c == 0 {
		w.truncated = true
	}
	if !w.truncated {
		w.out.WriteByte(c)
	}
}

func (w *nulTruncator) writeString(s string) {
	for i := 0; i < len(s); i++ {
		w.writeByte(s[i])
	}
}

func (w *nulTruncator) writeRune(r rune) {
	if !w.truncated {
		w.out.WriteRune(r)
	}
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
	words, _, _ := powerShellRead(s, false)
	return words
}

// powerShellRead is powerShellWords that, with track set, also returns the wildcard patterns,
// which cmdlets such as Get-Content expand themselves. PowerShell has no brace expansion. It
// also reports which words hold a variable PowerShell expands (see wordBuilder.expanded).
func powerShellRead(s string, track bool) (words, patterns []string, expanded []bool) {
	b := wordBuilder{track: track}
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
					b.writeByte(s[i])
					continue
				} else if s[i] == '"' {
					if i+1 < len(s) && s[i+1] == '"' {
						i++
					} else {
						break
					}
				}
				b.writeExpanding(s[i])
			}
		default:
			b.writeRaw(c)
		}
	}
	b.flush()
	return b.words, b.patterns, b.expanded
}

// cmdWords splits like cmd.exe: a caret escapes outside double quotes, and a backslash is ordinary.
func cmdWords(s string) []string {
	words, _ := cmdRead(s)
	return words
}

// cmdRead is cmdWords that also reports which words hold a %, which cmd.exe expands as a
// variable before it reads quotes and carets.
func cmdRead(s string) (words []string, expanded []bool) {
	var b wordBuilder
	inQuotes := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' {
			b.expands = true
		}
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
	return b.words, b.expanded
}
