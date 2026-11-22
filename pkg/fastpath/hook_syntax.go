package fastpath

import (
	"os"
	"strings"
)

func hookExpandPath(word, dir string) string {
	word = expandVariables(word, dir)
	if word == "~" || strings.HasPrefix(word, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			word = home + strings.TrimPrefix(word, "~")
		}
	}
	return word
}

// Keep find itself visible so its file-output actions can be inspected.
func hookUnwrap(words []string, reader *shellReader) []string {
	for len(words) > 0 && words[0] == "}" {
		words = words[1:]
	}
	if len(words) > 0 && programName(words[0]) == "find" {
		return words
	}
	return unwrapInvocation(words, reader)
}

func hookDotglob(command string) bool {
	for _, segment := range hookSegments(command) {
		w := posixWords(segment)
		if len(w) > 2 && w[0] == "shopt" && w[1] == "-s" {
			for _, v := range w[2:] {
				if v == "dotglob" {
					return true
				}
			}
		}
		if len(w) > 0 && shellPrograms[programName(w[0])] {
			for i, v := range w {
				if (v == "-O" || v == "+O") && i+1 < len(w) && w[i+1] == "dotglob" {
					return true
				}
			}
		}
	}
	return false
}
func hookHasBackslash(s string) bool {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == '\\' && quote != '\'' && i+1 < len(s) {
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if c == '\\' {
			if i+1 < len(s) && (s[i+1] == '\n' || s[i+1] == '\r') {
				continue
			}
			if i == 0 || isShellSpace(s[i-1]) || i+1 == len(s) || isShellSpace(s[i+1]) {
				continue
			}
			return true
		}
	}
	return false
}
func hookPowerShellPaths(s string) string { return strings.ReplaceAll(s, `\`, "/") }
func hookStdinInterpreter(words []string) bool {
	if len(words) == 0 {
		return false
	}
	switch programName(words[0]) {
	case "python", "python3", "node", "perl", "ruby", "php", "deno":
	default:
		return false
	}
	for _, word := range words[1:] {
		if word != "-" && !strings.HasPrefix(word, "-") {
			return false
		}
	}
	return true
}
func hookLiteralTargets(code string, dirs []string) []string {
	var targets []string
	for _, literal := range strings.FieldsFunc(code, func(r rune) bool { return strings.ContainsRune("\"'() ,;=+{}<>\n\r\t", r) }) {
		for _, dir := range dirs {
			literal := normalizePathSeparators(literal)
			if dir == hookUnknownDir {
				if hookUnknownRelative(literal) {
					targets = append(targets, "\x00u"+literal)
					continue
				}
				dir = ""
			}
			targets = append(targets, joinCwd(hookExpandPath(literal, dir), dir))
		}
	}
	return targets
}

// Only a writing subcommand makes a global directory option a write target.
func hookDirectoryTarget(name string, words []string) bool {
	if name == "unzip" {
		return true
	}
	if name == "tar" {
		for i := 1; i < len(words); i++ {
			w := words[i]
			if w == "--extract" || w == "--get" {
				return true
			}
			if w == "-C" || w == "-f" || w == "-T" || w == "-X" || w == "--file" || w == "--directory" {
				i++
				continue
			}
			if strings.HasPrefix(w, "--") {
				continue
			}
			if strings.HasPrefix(w, "-") {
				if strings.Contains(strings.TrimPrefix(w, "-"), "x") {
					return true
				}
				continue
			}
			if i == 1 {
				return strings.Contains(w, "x") && !strings.ContainsAny(w, "/.")
			}
			return false
		}
		return false
	}
	if name != "git" {
		return false
	}
	for i := 1; i < len(words); i++ {
		w := words[i]
		if w == "-C" || w == "-c" || w == "--git-dir" || w == "--work-tree" {
			i++
			continue
		}
		if strings.HasPrefix(w, "-") {
			continue
		}
		switch w {
		case "checkout", "restore", "reset", "apply", "stash", "merge", "pull", "switch":
			return true
		}
		return false
	}
	return false
}

// Home and absolute paths do not depend on the shell's uncertain cwd.
func hookUnknownRelative(word string) bool {
	// $PWD and $OLDPWD name the shell's current directories, which are unknown
	// here; expanding them from the guard's own environment would make the target
	// look absolute and skip protected-name matching.
	for _, prefix := range []string{"$PWD/", "${PWD}/", "$OLDPWD/", "${OLDPWD}/"} {
		if strings.HasPrefix(word, prefix) {
			return true
		}
	}
	return !isAbsoluteConfigDir(hookExpandPath(word, "")) && !strings.HasPrefix(word, "~") && !strings.HasPrefix(word, "$HOME") && !strings.HasPrefix(word, "${HOME}")
}
