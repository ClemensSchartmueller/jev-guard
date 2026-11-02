package fastpath

import (
	"strconv"
	"strings"
)

// maxShellNesting bounds how deep quoted strings are read as commands (sh -c "sh -c '...'").
const maxShellNesting = 3

// shellWords lists what a command's words may mean, for the transcript guard. The shell
// that will run the command is unknown and the shells disagree: a backslash escapes in POSIX
// shells and separates paths on Windows, while PowerShell escapes with a backtick and cmd.exe
// with a caret. So the command is read under each set of rules and all results are kept. This
// is deliberately not a shell parser: it adds spellings and never decides between them.
// It cannot see variables, globs, brace expansion, or anything else the shell computes.
func shellWords(command string) []string {
	seen := map[string]bool{}
	nested := map[string]bool{}
	var words []string
	var visit func(text string, depth int)
	visit = func(text string, depth int) {
		for _, split := range [][]string{posixWords(text), powerShellWords(text), cmdWords(text), strings.Fields(text)} {
			for _, word := range split {
				for _, form := range wordForms(word) {
					if !seen[form] {
						seen[form] = true
						words = append(words, form)
					}
				}
				// A quoted string may itself be a command, for sh -c or an interpreter.
				if depth < maxShellNesting && word != text && !nested[word] && strings.ContainsAny(word, " \t\r\n;|&<>()'\"`\\$^,") {
					nested[word] = true
					visit(word, depth+1)
				}
			}
		}
	}
	visit(command, 0)
	return words
}

// wordForms returns a word and the paths it may carry: parts split at operators and
// separators, and values attached to a short flag or an @.
func wordForms(word string) []string {
	forms := []string{word}
	if parts := strings.FieldsFunc(word, func(r rune) bool { return strings.ContainsRune(";|&<>()`=,:", r) }); len(parts) > 1 || (len(parts) == 1 && parts[0] != word) {
		forms = append(forms, parts...)
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

// ansiQuoted decodes the body of $'...' starting at i, returning it and the closing quote's index.
func ansiQuoted(s string, i int) (string, int) {
	simple := map[byte]byte{'a': 7, 'b': 8, 'e': 27, 'E': 27, 'f': 12, 'n': 10, 'r': 13, 't': 9, 'v': 11, '\\': '\\', '\'': '\'', '"': '"', '?': '?'}
	var out strings.Builder
	for ; i < len(s) && s[i] != '\''; i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			out.WriteByte(s[i])
			continue
		}
		i++
		c := s[i]
		if value, ok := simple[c]; ok {
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
