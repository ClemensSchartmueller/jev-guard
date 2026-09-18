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

	if len(roots) == 0 && cwd != "" {
		gitRoot := findGitRoot(cwd)
		if gitRoot != "" {
			if cleanGit, err := canonicalizePath(gitRoot); err == nil {
				roots = append(roots, cleanGit)
			}
		} else {
			if cleanCwd, err := canonicalizePath(cwd); err == nil {
				roots = append(roots, cleanCwd)
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
	if !filepath.IsAbs(targetPath) {
		absPath = filepath.Join(cwd, targetPath)
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

func canonicalizePath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
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
