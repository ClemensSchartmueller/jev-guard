package boundary

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

// Resolver checks whether target paths reside safely inside declared workspace boundaries.
type Resolver struct {
	WorkspaceRoots []string
}

// NewResolver initializes a Resolver with workspace paths, discovering git root if none provided.
func NewResolver(declaredRoots []string, cwd string) (*Resolver, error) {
	roots := make([]string, 0, len(declaredRoots))
	tooLong := false
	for _, root := range declaredRoots {
		cleanRoot, err := canonicalizePath(root)
		if errors.Is(err, ErrPathTooLong) {
			tooLong = true
		}
		if err == nil && cleanRoot != "" {
			roots = append(roots, cleanRoot)
		}
	}

	// A declared root too long to resolve must not be replaced by the cwd or Git root, which
	// could be broader. With no usable root, nothing is contained.
	if len(roots) == 0 && !tooLong {
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
	if errors.Is(err, ErrPathTooLong) {
		return false, err // the path itself is too long to repeat in a message
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

func joinPaths(base, rel string) string {
	cleanBase := normalizeSeparators(base)
	cleanRel := normalizeSeparators(rel)
	return path.Join(cleanBase, cleanRel)
}

// CanonicalizePath canonicalizes a path, evaluating symlinks and cleaning separators.
func CanonicalizePath(path string) (string, error) {
	return canonicalizePath(path)
}

// IsSubPath reports whether child resides lexically or physically inside parent.
func IsSubPath(parent, child string) bool {
	return isSubPath(parent, child)
}

// ErrPathTooLong is returned, wrapped, for a path longer than MaxResolvePathBytes. Such a
// path is not resolved: callers must treat it as unverifiable (not contained, ASK), never as
// contained or safe.
var ErrPathTooLong = errors.New("path is too long to resolve")

// MaxResolvePathBytes is the longest absolute, cleaned path the resolver will look up: 32,767
// on Windows (the extended-length path limit, counted here in UTF-8 bytes, which is never less
// than the UTF-16 units Windows counts) and 4,096 elsewhere (Linux PATH_MAX; macOS allows only
// 1,024). The OS cannot open a longer path, so there is nothing to resolve. The same values
// bound filesystem lookups in the fastpath transcript guard.
func MaxResolvePathBytes() int {
	return maxResolvePathBytesForOS(runtime.GOOS)
}

func maxResolvePathBytesForOS(goos string) int {
	if goos == "windows" {
		return 32767
	}
	return 4096
}

// evalSymlinks is a seam so tests can count filesystem resolutions.
var evalSymlinks = filepath.EvalSymlinks

func canonicalizePath(path string) (string, error) {
	if runtime.GOOS != "windows" && isWindowsDriveAbs(path) {
		clean := filepath.Clean(path)
		if err := checkPathLength(clean); err != nil {
			return "", err
		}
		return normalizeSeparators(clean), nil
	}

	// Check the length before filepath.Abs: on Windows, Abs itself fails on a very long
	// path, and that error must not hide the limit from callers that fail closed on it.
	// Making a path absolute never shortens it below its cleaned relative form by more
	// than its ".." components, so this only rejects paths far beyond the limit.
	if err := checkPathLength(filepath.Clean(path)); err != nil {
		return "", err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	clean := filepath.Clean(abs)
	if err := checkPathLength(clean); err != nil {
		return "", err
	}
	return resolveSymlinks(clean), nil
}

func checkPathLength(clean string) error {
	if limit := MaxResolvePathBytes(); len(clean) > limit {
		return fmt.Errorf("%w: %d bytes, limit %d", ErrPathTooLong, len(clean), limit)
	}
	return nil
}

// resolveSymlinks evaluates symlinks in an absolute, cleaned path. When the whole path does
// not resolve (a file about to be created), the deepest ancestor that does is resolved and the
// rest is appended as written.
//
// A cleaned path has no ".." components, so whether a prefix resolves is monotonic in its
// length: EvalSymlinks walks the components in order, so a prefix that fails makes every
// longer prefix fail the same way. The deepest resolvable ancestor is therefore found by
// binary search over the separator positions, with O(log n) EvalSymlinks calls, and the result
// is built with one concatenation. The previous one-ancestor-at-a-time walk was quadratic.
func resolveSymlinks(path string) string {
	if realPath, err := evalSymlinks(path); err == nil {
		return filepath.Clean(realPath)
	}

	volume := len(filepath.VolumeName(path))
	// ends[i] is where ancestor i ends; ancestors are ordered from the root down.
	var ends []int
	for i := volume; i < len(path); i++ {
		if os.IsPathSeparator(path[i]) {
			ends = append(ends, i)
		}
	}
	ancestor := func(i int) string {
		end := ends[i]
		if end == volume {
			return path[:end+1] // the root keeps its separator: "/" or `C:\`
		}
		return path[:end]
	}

	// Find the largest i whose ancestor resolves; ok holds its resolution.
	lo, hi := 0, len(ends) // the answer lies in [lo-1, hi-1]
	best, bestReal := -1, ""
	for lo < hi {
		mid := lo + (hi-lo)/2
		if realParent, err := evalSymlinks(ancestor(mid)); err == nil {
			best, bestReal = mid, realParent
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if best < 0 {
		return path
	}

	rest := path[ends[best]+1:]
	if rest == "" {
		return filepath.Clean(bestReal)
	}
	if len(bestReal) > 0 && os.IsPathSeparator(bestReal[len(bestReal)-1]) {
		return filepath.Clean(bestReal + rest)
	}
	return filepath.Clean(bestReal + string(filepath.Separator) + rest)
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
