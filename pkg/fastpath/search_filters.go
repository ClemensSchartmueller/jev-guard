package fastpath

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"jev-guard/pkg/boundary"
	"jev-guard/pkg/harness"
)

// Search and list tools select files with filter arguments as well as with their directory
// argument: Grep's glob and type, Glob's pattern, grep_search's Includes, and find_by_name's
// Pattern and Extensions. The sensitive and boundary checks only see the directory, so these
// filters are checked here before a safe read tool gets its trusted ALLOW:
//
//   - a filter that names a sensitive pattern (".env*", "*.pem") is a sensitive access;
//   - a filter that leaves the searched directory (absolute, "..", "~") is boundary-checked;
//   - any other filter that could still match a sensitive file name ("*", ".en?", "*.json")
//     gets no fast-path verdict, so the judge decides.
//
// Exclusion filters (Excludes, LS ignore) only narrow a search and are not checked. Content
// patterns (Grep pattern, grep_search Query) select lines, not files, and are not checked.

// searchFilter is one file-selecting argument value. ok is false for a value that is not a string.
// Filters in different groups apply together (find_by_name's Pattern and Extensions); a file
// must pass every group.
type searchFilter struct {
	key   string
	value string
	ok    bool
	group string
}

// searchFilters returns the file-selecting filter values of a safe read tool.
func searchFilters(call *harness.NormalizedToolCall) []searchFilter {
	if call == nil || !isSafeReadTool(call) {
		return nil
	}
	tool := strings.ToLower(strings.TrimSpace(call.ToolName))
	var out []searchFilter
	for key, raw := range call.RawArgs {
		lowerKey := strings.ToLower(key)
		var kind string
		group := "name"
		switch {
		case lowerKey == "glob" || lowerKey == "includes":
			kind = "glob"
		case lowerKey == "pattern" && (tool == "glob" || tool == "find_by_name"):
			kind = "glob"
		case lowerKey == "extensions" && tool == "find_by_name":
			kind = "extension"
			group = "extension"
		case lowerKey == "type" && tool == "grep":
			kind = "type"
		default:
			continue
		}
		values, ok := filterArgValues(raw)
		if !ok {
			out = append(out, searchFilter{key: key, group: group})
			continue
		}
		for _, value := range values {
			switch kind {
			case "extension":
				value = "*." + strings.TrimPrefix(value, ".")
			case "type":
				globs, known := narrowRipgrepTypes[strings.ToLower(value)]
				if !known {
					out = append(out, searchFilter{key: key, group: group})
					continue
				}
				for _, glob := range globs {
					out = append(out, searchFilter{key: key, value: glob, ok: true, group: group})
				}
				continue
			}
			out = append(out, searchFilter{key: key, value: value, ok: true, group: group})
		}
	}
	return out
}

// filterArgValues returns the string values of a filter argument, and false when any of them is
// not a string, since the tool's reading of such a value is unknown.
func filterArgValues(raw interface{}) ([]string, bool) {
	switch v := raw.(type) {
	case nil:
		return nil, true
	case string:
		return []string{v}, true
	case []string:
		return v, true
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			str, ok := item.(string)
			if !ok {
				return nil, false
			}
			out = append(out, str)
		}
		return out, true
	}
	return nil, false
}

// narrowRipgrepTypes are ripgrep file types (Grep's "type") whose built-in globs cannot match a
// default sensitive name, with those globs (ripgrep 14 --type-list). Any other type, json and sh
// among them (credentials.json, .env-style shell files), gets no fast-path ALLOW. A type that
// a user's ripgrep config redefines is outside what the gate can see.
var narrowRipgrepTypes = map[string][]string{
	"c":        {"*.[chh]", "*.[chh].in", "*.cats"},
	"cpp":      {"*.[chh]", "*.[ch]pp", "*.[ch]xx", "*.cc", "*.hh", "*.inl"},
	"cs":       {"*.cs"},
	"csharp":   {"*.cs"},
	"css":      {"*.css", "*.scss"},
	"dart":     {"*.dart"},
	"go":       {"*.go"},
	"graphql":  {"*.graphql", "*.graphqls"},
	"html":     {"*.ejs", "*.htm", "*.html"},
	"java":     {"*.java", "*.jsp", "*.jspx", "*.properties"},
	"js":       {"*.cjs", "*.js", "*.jsx", "*.mjs", "*.vue"},
	"kotlin":   {"*.kt", "*.kts"},
	"lua":      {"*.lua"},
	"markdown": {"*.markdown", "*.md", "*.mdown", "*.mdwn", "*.mdx", "*.mkd", "*.mkdn"},
	"md":       {"*.markdown", "*.md", "*.mdown", "*.mdwn", "*.mdx", "*.mkd", "*.mkdn"},
	"php":      {"*.php", "*.phtml"},
	"protobuf": {"*.proto"},
	"py":       {"*.py", "*.pyi"},
	"ruby":     {"*.gemspec", "*.rb", "*.rbw", "gemfile", "rakefile"},
	"rust":     {"*.rs"},
	"scala":    {"*.sbt", "*.scala"},
	"sql":      {"*.psql", "*.sql"},
	"swift":    {"*.swift"},
	"toml":     {"*.toml", "cargo.lock"},
	"ts":       {"*.cts", "*.mts", "*.ts", "*.tsx"},
	"txt":      {"*.txt"},
	"xml":      {"*.xml", "*.xsd", "*.xsl", "*.xslt", "*.xhtml"},
	"yaml":     {"*.yaml", "*.yml"},
	"zig":      {"*.zig"},
}

// checkSensitiveFilters returns a sensitive-file reason when a search filter names a sensitive
// pattern, compared case-insensitively after {a,b} alternatives are expanded and glob escapes
// and brackets are removed (".env*", "*.{env,go}", ".[e]nv", "**/*.pem").
func (f *Filter) checkSensitiveFilters(call *harness.NormalizedToolCall) string {
	for _, filter := range searchFilters(call) {
		if !filter.ok {
			continue // judged as unverifiable by checkSearchFilters
		}
		expansions, ok := expandBraces(strings.ToLower(filter.value), maxPatternExpansions)
		if !ok || len(filter.value) > maxPathLikeBytes {
			continue
		}
		for _, expanded := range expansions {
			stripped := normalizePathSeparators(strings.NewReplacer(`\`, "", "[", "", "]", "").Replace(expanded))
			// "\" is an escape in a glob and a separator on Windows: read it both ways.
			for _, reading := range []string{stripped, normalizePathSeparators(expanded)} {
				for _, s := range f.sensitiveFiles {
					token := strings.TrimPrefix(strings.ToLower(normalizePathSeparators(s)), "*")
					if token == "" {
						continue
					}
					dirToken := strings.TrimSuffix(token, "/")
					if strings.Contains(reading, token) ||
						(dirToken != token && containsSegment(reading, dirToken)) {
						return fmt.Sprintf("Search filter %s %q selects sensitive file or credential pattern: %s", filter.key, filter.value, s)
					}
				}
			}
		}
	}
	return ""
}

func containsSegment(p, segment string) bool {
	for _, part := range strings.Split(p, "/") {
		if part == segment {
			return true
		}
	}
	return false
}

// checkSearchFilters checks the search filters that checkSensitiveFilters let through. It returns
// a boundary reason for a filter that leaves the searched directory, and broad=true for one that
// could still match a sensitive file name or cannot be read, which must not get a local ALLOW.
// A non-nil error wraps boundary.ErrResolutionLimit.
func (f *Filter) checkSearchFilters(call *harness.NormalizedToolCall) (reason string, broad bool, err error) {
	filters := searchFilters(call)
	if len(filters) == 0 {
		return "", false, nil
	}
	samples, dirSamples := f.sensitiveSampleNames()
	// A group is broad when any of its values is; groups apply together, so the call is broad
	// only when every group is. Treating each group on its own is a superset of the files a
	// file must match in all of them.
	groupBroad := map[string]bool{}
	for _, filter := range filters {
		if !filter.ok || len(filter.value) > maxPathLikeBytes {
			groupBroad[filter.group] = true
			continue
		}
		reason, err := f.checkFilterBoundary(call, filter)
		if reason != "" || err != nil {
			return reason, false, err
		}
		groupBroad[filter.group] = groupBroad[filter.group] || filterMayMatchSensitive(filter.value, samples, dirSamples)
	}
	for _, b := range groupBroad {
		if !b {
			return "", false, nil
		}
	}
	return "", true, nil
}

// checkFilterBoundary boundary-checks a filter that is absolute, starts with "~", or has a ".."
// segment. A relative filter is read below the tool's directory argument, which the boundary
// check already covers.
func (f *Filter) checkFilterBoundary(call *harness.NormalizedToolCall, filter searchFilter) (string, error) {
	value := filter.value
	outside := fmt.Sprintf("Search filter %s escapes workspace boundaries: %s", filter.key, value)
	if strings.HasPrefix(value, "~") {
		return outside, nil
	}
	// "\" is a separator on Windows and an escape elsewhere; for "..", read it both ways.
	for _, segment := range strings.Split(normalizePathSeparators(value), "/") {
		if segment == ".." {
			return outside, nil
		}
	}
	slashed := value
	if runtime.GOOS == "windows" {
		slashed = normalizePathSeparators(value)
	}
	if !strings.HasPrefix(slashed, "/") && !(runtime.GOOS == "windows" && isAbsoluteSlashPath(slashed)) {
		return "", nil
	}
	checker := f.resolveBoundaryChecker(call)
	if checker == nil {
		return fmt.Sprintf("Workspace boundaries cannot be resolved for search filter %s: %s", filter.key, value), nil
	}
	prefix := staticGlobPrefix(slashed)
	contained, err := checker.IsPathContained(filepath.FromSlash(prefix), call.Cwd)
	if errors.Is(err, boundary.ErrResolutionLimit) {
		return "", err
	}
	if err != nil || !contained {
		return outside, nil
	}
	return "", nil
}

// staticGlobPrefix returns the leading segments of a slash-separated absolute glob that hold no
// glob syntax: the directory the glob cannot leave. "/" and "C:/" are kept as roots.
func staticGlobPrefix(p string) string {
	segments := strings.Split(p, "/")
	end := 0
	for end < len(segments) && !strings.ContainsAny(segments[end], `*?[]{}\`) {
		end++
	}
	prefix := strings.Join(segments[:end], "/")
	if prefix == "" || (len(prefix) == 2 && prefix[1] == ':') {
		prefix += "/"
	}
	return prefix
}

// filterMayMatchSensitive reports whether a glob could match a sensitive name: its last segment
// matches a sample file name, or a directory segment other than a bare "*" or "**" matches a
// sample directory name. A wildcard-only directory level is allowed because the file name must
// still pass, so "src/**/*.ts" stays narrow while "*", ".en?" and "*.json" do not.
func filterMayMatchSensitive(value string, samples, dirSamples []string) bool {
	expansions, ok := expandBraces(strings.ToLower(value), maxPatternExpansions)
	if !ok {
		return true
	}
	for _, expanded := range expansions {
		// Read "\" as a glob escape and as a Windows separator.
		for _, reading := range []string{expanded, normalizePathSeparators(expanded)} {
			segments := strings.Split(strings.TrimSuffix(reading, "/"), "/")
			last := len(segments) - 1
			for i, segment := range segments {
				names := dirSamples
				if i == last {
					names = samples
				} else if segment == "*" || segment == "**" {
					continue
				}
				for _, name := range names {
					// An inexact match is a possible match (see globMatch).
					if matched, exact := globMatch(segment, name); matched || !exact {
						return true
					}
				}
			}
		}
	}
	return false
}

// sensitiveSampleNames returns file and directory names that the sensitive patterns match, for
// testing whether a glob could reach one. Sensitive patterns match as substrings, so each
// file token is also tried with text around it (".env.a", "a.env").
func (f *Filter) sensitiveSampleNames() (samples, dirSamples []string) {
	for _, s := range f.sensitiveFiles {
		token := strings.TrimPrefix(strings.ToLower(normalizePathSeparators(s)), "*")
		token = strings.NewReplacer("*", "a", "?", "a").Replace(token)
		if token == "" {
			continue
		}
		segments := strings.Split(strings.TrimSuffix(token, "/"), "/")
		if strings.HasSuffix(token, "/") {
			dirSamples = append(dirSamples, segments...)
			// Any file inside a sensitive directory is sensitive.
			samples = append(samples, path.Base(strings.TrimSuffix(token, "/")))
			continue
		}
		dirSamples = append(dirSamples, segments[:len(segments)-1]...)
		base := segments[len(segments)-1]
		samples = append(samples, base, "a"+base, base+".a", "a"+base+".a")
	}
	return samples, dirSamples
}
