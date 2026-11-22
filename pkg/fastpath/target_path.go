package fastpath

import (
	"net/url"
	"strings"

	"jev-guard/pkg/harness"
)

// unverifiableTargetReason is reported when a tool target cannot be tied to the one path the
// tool will open, so no local check can vouch for it.
const unverifiableTargetReason = "Target path cannot be verified: it does not name a single local path as given"

// LocalTargetPaths returns the local paths the sensitive and boundary checks must cover for a
// tool target. A plain target is returned as is: the tool opens the name exactly as given, so
// it is never trimmed or rewritten. A file:// URI yields its percent-decoded path and, when the
// escaped spelling differs, that spelling too, since a consumer that does not decode opens the
// literal name. Other URLs are returned unchanged.
//
// ok is false when the target cannot be tied to the path the tool opens: leading or trailing
// whitespace (Unicode included, on any target, since " file:///x" is a relative name), or a file URI that does not parse, names a host other than
// "localhost", or carries user info, a port, a query, a fragment, a NUL or an empty path.
// Callers must not allow or verify such a target locally.
func LocalTargetPaths(target string) ([]string, bool) {
	if target != strings.TrimSpace(target) {
		return nil, false
	}
	if isURL(target) {
		return []string{target}, true
	}
	if !isFileURI(target) {
		return []string{target}, true
	}
	decoded, literal, ok := parseFileURI(target)
	if !ok {
		return nil, false
	}
	if literal != decoded {
		return []string{decoded, literal}, true
	}
	return []string{decoded}, true
}

// parseFileURI parses a file:// URI into its percent-decoded path and its escaped spelling.
// A Windows drive path ("file:///C:/x") loses the slash before the drive letter.
func parseFileURI(raw string) (decoded, literal string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Scheme, "file") || u.Opaque != "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") {
		return "", "", false
	}
	if host := u.Host; host != "" && !strings.EqualFold(host, "localhost") {
		return "", "", false // a remote host, a port, or a drive letter in the host position
	}
	decoded, literal = dropDriveSlash(u.Path), dropDriveSlash(u.EscapedPath())
	if decoded == "" || strings.ContainsRune(decoded, 0) || strings.ContainsRune(literal, 0) {
		return "", "", false
	}
	return decoded, literal, true
}

func dropDriveSlash(p string) string {
	if len(p) >= 3 && p[0] == '/' && isDriveLetter(p[1]) && p[2] == ':' {
		return p[1:]
	}
	return p
}

// hasUnverifiableTarget reports whether the call names a target that LocalTargetPaths rejects.
func hasUnverifiableTarget(call *harness.NormalizedToolCall) bool {
	if call == nil || call.TargetPath == "" {
		return false
	}
	_, ok := LocalTargetPaths(call.TargetPath)
	return !ok
}
