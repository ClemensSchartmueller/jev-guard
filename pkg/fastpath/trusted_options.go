package fastpath

import (
	"slices"
	"strings"

	"jev-guard/pkg/config"
)

type trustedCommandSpec struct {
	options        []string
	allowOperands  bool
	allowSeparator bool
	nameOnly       bool
	extraOption    func(string) bool
}

var defaultTrustedPrefixes = config.DefaultTrustedCommands()

var trustedInspectionCommands = map[string]trustedCommandSpec{
	"git status": {
		options:       []string{"-s", "--short", "-b", "--branch", "--porcelain", "--porcelain=v1", "--porcelain=v2"},
		allowOperands: true, allowSeparator: true,
	},
	"git diff": {
		options:       []string{"-p", "--patch", "--stat", "--numstat", "--shortstat", "--name-only", "--name-status", "--cached", "--staged", "--no-ext-diff", "--no-textconv"},
		allowOperands: true, allowSeparator: true,
	},
	"git log": {
		options:       []string{"-p", "--patch", "--oneline", "--stat", "--name-only", "--name-status", "--graph", "--decorate", "--no-decorate", "--all", "--no-ext-diff", "--no-textconv"},
		allowOperands: true, allowSeparator: true, extraOption: gitLogCountOption,
	},
	"git branch": {
		// A bare operand can create a branch without any options.
		options: []string{"--list", "-a", "--all", "-r", "--remotes", "-v", "-vv", "--verbose"},
	},
	"git show": {
		options:       []string{"-p", "--patch", "--oneline", "--stat", "--name-only", "--name-status", "--no-ext-diff", "--no-textconv"},
		allowOperands: true, allowSeparator: true,
	},
	"ls":               {allowOperands: true, nameOnly: true, extraOption: listingOption},
	"dir":              {allowOperands: true, nameOnly: true, extraOption: listingOption},
	"pwd":              {nameOnly: true, options: []string{"-L", "-P"}},
	"echo":             {allowOperands: true, nameOnly: true, options: []string{"-n"}},
	"whoami":           {nameOnly: true},
	"which":            {allowOperands: true, nameOnly: true, options: []string{"-a"}},
	"where.exe":        {allowOperands: true, nameOnly: true},
	"node -v":          {nameOnly: true},
	"go version":       {nameOnly: true},
	"python --version": {nameOnly: true},
}

func allowsTrustedCommandArgs(prefix, args string) bool {
	spec, builtIn := trustedInspectionCommands[prefix]
	if !builtIn {
		// Preserve user opt-ins, and require an explicit policy for every default.
		return !slices.Contains(defaultTrustedPrefixes, prefix)
	}

	for _, words := range [][]string{posixWords(args), powerShellWords(args), cmdWords(args)} {
		for _, word := range words {
			if spec.allowSeparator && word == "--" {
				// Some shells may consume the separator. Check later
				// tokens as potential options as well.
				continue
			}
			if spec.allowOperands && !strings.HasPrefix(word, "-") {
				continue
			}
			if slices.Contains(spec.options, word) || (spec.extraOption != nil && spec.extraOption(word)) {
				continue
			}
			return false
		}
	}
	return true
}

func gitLogCountOption(word string) bool {
	return strings.HasPrefix(word, "-") && len(word) > 1 && strings.Trim(word[1:], "0123456789") == ""
}

func listingOption(word string) bool {
	switch word {
	case "--all", "--almost-all", "--human-readable", "--color", "--color=auto", "--color=always", "--color=never":
		return true
	}
	// Accept bundles of short flags for listing format, sorting, and visibility.
	const shortListingOptions = "aAdFhilrSt"
	return strings.HasPrefix(word, "-") && len(word) > 1 && strings.Trim(word[1:], shortListingOptions) == ""
}
