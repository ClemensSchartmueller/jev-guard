package boundary

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf16"
)

// Resolver checks whether target paths reside safely inside declared workspace boundaries.
type Resolver struct {
	WorkspaceRoots []string
}

// NewResolver initializes a Resolver with workspace paths, discovering git root if none provided.
func NewResolver(declaredRoots []string, cwd string) (*Resolver, error) {
	roots := make([]string, 0, len(declaredRoots))
	declared := false
	for _, root := range declaredRoots {
		if strings.TrimSpace(root) == "" {
			continue
		}
		declared = true
		cleanRoot, err := canonicalizePath(root)
		if err == nil && cleanRoot != "" {
			roots = append(roots, cleanRoot)
		}
	}

	// The cwd or Git root is used only when the agent declared no workspace root. A declared
	// root that cannot be resolved (a resolution limit, ENOTDIR, EACCES, a symlink loop) must
	// not be replaced by them, because they can be broader than what was declared. With no
	// usable root, nothing is contained and the call is asked about.
	if !declared {
		effectiveCwd := cwd
		if effectiveCwd == "" {
			effectiveCwd, _ = os.Getwd()
		}
		if effectiveCwd != "" {
			gitRoot := findGitRoot(effectiveCwd)
			if gitRoot != "" {
				if cleanGit, err := canonicalizePath(gitRoot); err == nil {
					roots = append(roots, cleanGit)
				}
			} else {
				if cleanCwd, err := canonicalizePath(effectiveCwd); err == nil {
					roots = append(roots, cleanCwd)
				}
			}
		}
	}

	return &Resolver{WorkspaceRoots: roots}, nil
}

// IsPathContained checks if targetPath falls within any recognized workspace root.
func (r *Resolver) IsPathContained(targetPath string, cwd string) (bool, error) {
	if strings.TrimSpace(targetPath) == "" {
		return true, nil // No target specified to violate boundaries
	}

	absPath := targetPath
	if !isAbsPath(targetPath) {
		baseDir := cwd
		if baseDir == "" {
			baseDir, _ = os.Getwd()
		}
		absPath = joinPaths(baseDir, targetPath)
	}

	cleanTarget, err := canonicalizePath(absPath)
	if errors.Is(err, ErrResolutionLimit) {
		return false, err // the path itself may be too long to repeat in a message
	}
	if err != nil {
		return false, fmt.Errorf("unable to resolve path %s: %w", targetPath, err)
	}

	for _, root := range r.WorkspaceRoots {
		if isSubPath(root, cleanTarget) {
			return true, nil
		}
	}

	return false, nil
}

func isAbsPath(p string) bool {
	if filepath.IsAbs(p) || isSlashRoot(p) {
		return true
	}
	if isWindowsDriveAbs(p) {
		return true
	}
	return false
}

func isSlashRoot(p string) bool {
	return strings.HasPrefix(p, "/") || strings.HasPrefix(p, "\\")
}

func isWindowsDriveAbs(p string) bool {
	return len(p) >= 3 && isDriveLetter(p[0]) && p[1] == ':' && (p[2] == '/' || p[2] == '\\')
}

func isDriveLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func normalizeSeparators(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}

// joinPaths joins rel to base without cleaning: the walk applies ".." where the OS does, after
// the symlink before it is followed.
func joinPaths(base, rel string) string {
	return JoinPath(normalizeSeparators(base), normalizeSeparators(rel))
}

// CanonicalizePath canonicalizes a path, evaluating symlinks and cleaning separators.
func CanonicalizePath(path string) (string, error) {
	return canonicalizePath(path)
}

// IsSubPath reports whether child resides lexically or physically inside parent.
func IsSubPath(parent, child string) bool {
	return isSubPath(parent, child)
}

// ErrPathTooLong is returned, wrapped, for a path longer than MaxResolvePathLength. Such a
// path is not resolved: callers must treat it as unverifiable (not contained, ASK), never as
// contained or safe. It matches ErrResolutionLimit.
var ErrPathTooLong error = &limitError{"path is too long to resolve"}

// MaxResolvePathLength is the longest absolute, cleaned path the resolver will look up, in the
// units the OS counts (see ResolvePathLength): 32,767 UTF-16 code units on Windows (the
// extended-length path limit), 1,024 bytes on macOS (PATH_MAX there) and 4,096 bytes
// elsewhere (Linux PATH_MAX). The OS cannot look up a longer path, so there is nothing to
// resolve; and the walk must not mistake the OS's "name too long" for a missing component.
// Every lookup the walk makes, including after a symlink target is spliced in, is checked
// against it. This limit is separate from the evaluation's work budget (WorkBudget).
func MaxResolvePathLength() int {
	return maxResolvePathLengthForOS(runtime.GOOS)
}

func maxResolvePathLengthForOS(goos string) int {
	switch goos {
	case "windows":
		return 32767
	case "darwin", "ios":
		return 1024
	}
	return 4096
}

// ResolvePathLength is the length of p in the units MaxResolvePathLength counts: UTF-16 code
// units on Windows, where a 3-byte UTF-8 character such as a CJK ideograph is one unit, and
// bytes elsewhere.
func ResolvePathLength(p string) int {
	return pathLengthForOS(p, runtime.GOOS)
}

func pathLengthForOS(p, goos string) int {
	if goos != "windows" {
		return len(p)
	}
	n := 0
	for _, r := range p {
		n += utf16Units(r)
	}
	return n
}

// utf16Units is the UTF-16 length of r. Invalid UTF-8 decodes as U+FFFD, one unit, which is
// also what it becomes when the path is passed to Windows.
func utf16Units(r rune) int {
	if l := utf16.RuneLen(r); l > 0 {
		return l
	}
	return 1
}

func canonicalizePath(path string) (string, error) {
	if runtime.GOOS != "windows" && isWindowsDriveAbs(path) {
		clean := filepath.Clean(path)
		if err := checkPathLength(clean); err != nil {
			return "", err
		}
		return normalizeSeparators(clean), nil
	}

	abs, err := absInput(path)
	if err != nil {
		return "", err
	}
	return withEvaluation(func(e *evaluation) (string, error) {
		return e.resolve(abs, false)
	})
}

func checkPathLength(clean string) error {
	// A path's UTF-16 length never exceeds its UTF-8 length, so most paths need no count.
	limit := MaxResolvePathLength()
	if len(clean) <= limit {
		return nil
	}
	if n := ResolvePathLength(clean); n > limit {
		return fmt.Errorf("%w: length %d, limit %d", ErrPathTooLong, n, limit)
	}
	return nil
}

func isSubPath(parent, child string) bool {
	return isSubPathForOS(parent, child, runtime.GOOS)
}

func isSubPathForOS(parent, child, goos string) bool {
	normParent := normalizeSeparators(filepath.Clean(parent))
	normChild := normalizeSeparators(filepath.Clean(child))

	if goos == "windows" {
		normParent = strings.ToLower(normParent)
		normChild = strings.ToLower(normChild)
	}

	if normParent == normChild {
		return true
	}

	if !strings.HasSuffix(normParent, "/") {
		normParent += "/"
	}

	return strings.HasPrefix(normChild, normParent)
}

// FindGitRoot returns the nearest directory at or above startDir that
// contains a .git entry, or "" if there is none.
func FindGitRoot(startDir string) string {
	return findGitRoot(startDir)
}

func findGitRoot(startDir string) string {
	curr := filepath.Clean(startDir)
	if checkPathLength(curr) != nil {
		return ""
	}
	for {
		gitPath := filepath.Join(curr, ".git")
		if info, err := os.Stat(gitPath); err == nil && (info.IsDir() || !info.IsDir()) {
			return curr
		}

		parent := filepath.Dir(curr)
		if parent == curr {
			break
		}
		curr = parent
	}
	return ""
}
