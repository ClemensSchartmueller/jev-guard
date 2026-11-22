package fastpath

import (
	"path"
	"strings"
	"unicode/utf8"
)

// globMatch matches one path segment of a glob against name the way Bash and ripgrep read it,
// for the anti-tampering checks. Go's path.Match rejects or misreads bracket expressions both
// accept: POSIX classes ([[:alpha:]]), equivalence classes ([[=g=]]), collating symbols
// ([[.g.]]), a "]" first in a class ([]fg]) and "!" negation ([!x]). globMatch rewrites them
// into path.Match syntax first (see translateGlob).
//
// exact is false when the pattern holds a bracket expression the check cannot read exactly
// (an unknown class name, a multi-character collating element). That expression is matched as
// any one character, a superset of what the shell would match, and callers treat an inexact
// match as singling out the name it matches, so it fails closed. A pattern path.Match still
// rejects is reported as matching, inexactly.
//
// Inside a bracket expression Bash reads a backslash as an escape and ripgrep as a literal
// ([f-h\] is a class in ripgrep and an unclosed "[" in Bash). A pattern the two read
// differently is matched both ways, a match either way counts, and it is inexact.
func globMatch(pattern, name string) (matched, exact bool) {
	escaped, escapedExact := translateGlob(pattern, false)
	matched, exact = matchTranslated(escaped, escapedExact, name)
	if strings.Contains(pattern, "[") && strings.Contains(pattern, `\`) {
		literal, literalExact := translateGlob(pattern, true)
		if literal != escaped {
			literalMatched, _ := matchTranslated(literal, literalExact, name)
			return matched || literalMatched, false
		}
	}
	return matched, exact
}

func matchTranslated(translated string, exact bool, name string) (matched, isExact bool) {
	matched, err := path.Match(translated, name)
	if err != nil {
		return true, false
	}
	return matched, exact
}

// translateGlob rewrites a Bash or ripgrep glob into path.Match syntax. Outside brackets the
// grammars agree, except that a trailing backslash is a literal and a "[" without a closing
// "]" is a literal in Bash (ripgrep rejects the pattern, so it opens nothing). literalBackslash
// reads a backslash inside a bracket expression as ripgrep does, as a member.
func translateGlob(pattern string, literalBackslash bool) (string, bool) {
	if !strings.ContainsAny(pattern, `[\`) {
		return pattern, true
	}
	var out strings.Builder
	exact := true
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			if i+1 == len(pattern) {
				out.WriteString(`\\`)
				continue
			}
			out.WriteString(pattern[i : i+2])
			i++
		case '[':
			class, end, classExact, ok := translateClass(pattern, i, literalBackslash)
			if !ok {
				out.WriteString(`\[`)
				continue
			}
			if !classExact {
				exact = false
				class = "?"
			}
			out.WriteString(class)
			i = end
		default:
			out.WriteByte(pattern[i])
		}
	}
	return out.String(), exact
}

// runeRange is an inclusive range of characters in a bracket expression.
type runeRange struct{ lo, hi rune }

// posixClasses lists the characters of each POSIX class. Patterns and names are compared
// lower-cased, so the case classes take both cases. Classes a locale may extend to letters
// and symbols outside ASCII take every non-ASCII character.
var posixClasses = func() map[string][]runeRange {
	nonASCII := runeRange{0x80, utf8.MaxRune}
	letters := []runeRange{{'a', 'z'}, {'A', 'Z'}, nonASCII}
	return map[string][]runeRange{
		"alpha":  letters,
		"lower":  letters,
		"upper":  letters,
		"alnum":  append([]runeRange{{'0', '9'}}, letters...),
		"word":   append([]runeRange{{'0', '9'}, {'_', '_'}}, letters...),
		"digit":  {{'0', '9'}},
		"xdigit": {{'0', '9'}, {'a', 'f'}, {'A', 'F'}},
		"space":  {{' ', ' '}, {'\t', '\r'}},
		"blank":  {{' ', ' '}, {'\t', '\t'}},
		"punct":  {{'!', '/'}, {':', '@'}, {'[', '`'}, {'{', '~'}, nonASCII},
		"graph":  {{'!', '~'}, nonASCII},
		"print":  {{' ', '~'}, nonASCII},
		"cntrl":  {{0, 0x1f}, {0x7f, 0x7f}},
		"ascii":  {{0, 0x7f}},
	}
}()

// translateClass reads the bracket expression that opens at pattern[start] and returns it in
// path.Match syntax with every member escaped, the index of its closing "]", and whether it
// was read exactly. ok is false when no "]" closes it, so the "[" is a literal.
//
// As in Bash and ripgrep, "!" or "^" right after "[" negates the class, and a "]" right after
// that (or after "[") is a member.
func translateClass(pattern string, start int, literalBackslash bool) (class string, end int, exact, ok bool) {
	i := start + 1
	negate := i < len(pattern) && (pattern[i] == '!' || pattern[i] == '^')
	if negate {
		i++
	}
	exact = true
	var members []runeRange
	for first := true; i < len(pattern); first = false {
		if pattern[i] == ']' && !first {
			return writeClass(members, negate), i, exact, true
		}
		var lo rune
		if name, delim, next, found := bracketName(pattern, i); found {
			i = next
			if delim == ':' {
				ranges, known := posixClasses[name]
				members = append(members, ranges...)
				exact = exact && known
				continue
			}
			// [=x=] and [.x.] name one character; a longer name is a locale's collating element.
			r, size := utf8.DecodeRuneInString(name)
			if name == "" || size != len(name) {
				exact = false
				continue
			}
			lo = r
		} else {
			lo, i = readClassChar(pattern, i, literalBackslash)
		}
		var hi rune
		hi, i, exact = readRangeEnd(pattern, i, lo, exact, literalBackslash)
		members = append(members, runeRange{lo, hi})
	}
	return "", 0, false, false
}

// bracketName reads a [:name:], [=x=] or [.x.] element at pattern[i].
func bracketName(pattern string, i int) (name string, delim byte, next int, found bool) {
	if pattern[i] != '[' || i+1 >= len(pattern) || !strings.ContainsRune(":=.", rune(pattern[i+1])) {
		return "", 0, 0, false
	}
	delim = pattern[i+1]
	close := strings.Index(pattern[i+2:], string(delim)+"]")
	if close < 0 {
		return "", 0, 0, false
	}
	return pattern[i+2 : i+2+close], delim, i + 2 + close + 2, true
}

// readClassChar reads one member character at pattern[i], with a backslash escaping it unless
// literalBackslash is set.
func readClassChar(pattern string, i int, literalBackslash bool) (rune, int) {
	if !literalBackslash && pattern[i] == '\\' && i+1 < len(pattern) {
		i++
	}
	r, size := utf8.DecodeRuneInString(pattern[i:])
	return r, i + size
}

// readRangeEnd reads "-x" after a member at pattern[i], giving the range's upper end. A "-"
// before the closing "]" is a member. An upper end written as a bracketed name is not read
// exactly.
func readRangeEnd(pattern string, i int, lo rune, exact, literalBackslash bool) (rune, int, bool) {
	if i+1 >= len(pattern) || pattern[i] != '-' || pattern[i+1] == ']' {
		return lo, i, exact
	}
	if _, _, next, found := bracketName(pattern, i+1); found {
		return lo, next, false
	}
	hi, next := readClassChar(pattern, i+1, literalBackslash)
	return hi, next, exact
}

// writeClass writes members as a path.Match class, escaping every character.
func writeClass(members []runeRange, negate bool) string {
	var out strings.Builder
	out.WriteByte('[')
	if negate {
		out.WriteByte('^')
	}
	for _, m := range members {
		out.WriteByte('\\')
		out.WriteRune(m.lo)
		if m.hi != m.lo {
			out.WriteString(`-\`)
			out.WriteRune(m.hi)
		}
	}
	out.WriteByte(']')
	return out.String()
}
