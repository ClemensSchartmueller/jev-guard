package boundary

import (
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
	for _, root := range declaredRoots {
		if cleanRoot, err := canonicalizePath(root); err == nil && cleanRoot != "" {
			roots = append(roots, cleanRoot)
		}
	}

	if len(roots) == 0 {
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

func canonicalizePath(path string) (string, error) {
	if runtime.GOOS != "windows" && isWindowsDriveAbs(path) {
		return normalizeSeparators(filepath.Clean(path)), nil
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	clean := filepath.Clean(abs)
	return resolveSymlinks(clean), nil
}

func resolveSymlinks(path string) string {
	if realPath, err := filepath.EvalSymlinks(path); err == nil {
		return filepath.Clean(realPath)
	}

	curr := path
	var parts []string
	for {
		parent := filepath.Dir(curr)
		if parent == curr {
			break
		}
		parts = append([]string{filepath.Base(curr)}, parts...)
		if realParent, err := filepath.EvalSymlinks(parent); err == nil {
			result := realParent
			for _, part := range parts {
				result = filepath.Join(result, part)
			}
			return filepath.Clean(result)
		}
		curr = parent
	}

	return path
}

func isSubPath(parent, child string) bool {
	// Normalize drive letters and separators for accurate cross-platform boundary checks
	normParent := strings.ToLower(normalizeSeparators(filepath.Clean(parent)))
	normChild := strings.ToLower(normalizeSeparators(filepath.Clean(child)))

	if normParent == normChild {
		return true
	}

	if !strings.HasSuffix(normParent, "/") {
		normParent += "/"
	}

	return strings.HasPrefix(normChild, normParent)
}

func findGitRoot(startDir string) string {
	curr := filepath.Clean(startDir)
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
