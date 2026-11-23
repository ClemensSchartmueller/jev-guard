package fastpath

import (
	"slices"
	"strings"
)

var trustedInspectionOptions = map[string][]string{
	"git status": {"-s", "--short", "-b", "--branch", "--porcelain", "--porcelain=v1", "--porcelain=v2"},
	"git diff":   {"-p", "--patch", "--stat", "--numstat", "--shortstat", "--name-only", "--name-status", "--cached", "--staged", "--no-ext-diff", "--no-textconv"},
	"git log":    {"-p", "--patch", "--oneline", "--stat", "--name-only", "--name-status", "--graph", "--decorate", "--no-decorate", "--all", "--no-ext-diff", "--no-textconv"},
	"git branch": {"--list", "-a", "--all", "-r", "--remotes", "-v", "-vv", "--verbose"},
	"git show":   {"-p", "--patch", "--oneline", "--stat", "--name-only", "--name-status", "--no-ext-diff", "--no-textconv"},
	"ls":         {"--all", "--almost-all", "--human-readable", "--color"},
	"dir":        {"--all", "--almost-all", "--human-readable", "--color"},
	"pwd":        {"-L", "-P"},
	"echo":       {"-n"},
	"whoami":     {},
	"which":      {"-a"},
	"where.exe":  {},
}

func trustedCommandOptions(prefix, args string) bool {
	if args == "" {
		return true
	}
	switch prefix {
	case "node -v", "go version", "python --version":
		return false
	}
	options, builtIn := trustedInspectionOptions[prefix]
	if !builtIn {
		// User-configured command prefixes retain their existing argument checks.
		return true
	}

	for _, words := range [][]string{posixWords(args), powerShellWords(args), cmdWords(args)} {
		pathsOnly := false
		for _, word := range words {
			if pathsOnly {
				continue
			}
			switch {
			case word == "--" && prefix != "git branch" && strings.HasPrefix(prefix, "git "):
				pathsOnly = true
			case slices.Contains(options, word):
			case prefix == "git branch":
				// A bare operand can create a branch without any options.
				return false
			case !strings.HasPrefix(word, "-"):
			case (prefix == "ls" || prefix == "dir") && listingOption(word):
			case prefix == "git log" && len(word) > 1 && strings.Trim(word[1:], "0123456789") == "":
			default:
				return false
			}
		}
	}
	return true
}

func listingOption(word string) bool {
	return strings.HasPrefix(word, "--color=") ||
		(len(word) > 1 && strings.Trim(word[1:], "aAdFhilrSt") == "")
}
