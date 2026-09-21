package boundary

import (
	"fmt"
	"os"
	"path/filepath"
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
	if !filepath.IsAbs(targetPath) && !isSlashRoot(targetPath) {
		baseDir := cwd
		if baseDir == "" {
			baseDir, _ = os.Getwd()
		}
		absPath = filepath.Join(baseDir, targetPath)
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

func isSlashRoot(p string) bool {
	return strings.HasPrefix(p, "/") || strings.HasPrefix(p, "\\")
}

func canonicalizePath(path string) (string, error) {
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
	// Normalize drive letters and case on Windows for accurate boundary checks
	normParent := strings.ToLower(filepath.Clean(parent))
	normChild := strings.ToLower(filepath.Clean(child))

	if normParent == normChild {
		return true
	}

	parentWithSep := normParent
	if !strings.HasSuffix(parentWithSep, string(filepath.Separator)) {
		parentWithSep += string(filepath.Separator)
	}

	return strings.HasPrefix(normChild, parentWithSep)
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
