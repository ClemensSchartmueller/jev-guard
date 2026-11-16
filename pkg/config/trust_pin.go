package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// pinnedConfig is what a pinned lookup proved: the identities, read from open handles, of a
// directory and of the regular, non-symlink config file found under its name in that
// directory. Both identities come from handles, not from a second path lookup, so a path
// swapped after a step cannot change what was compared.
type pinnedConfig struct {
	dir, file os.FileInfo
}

// pinFunc is the signature of pinRecordedConfig. step runs before each open with the path
// about to be opened; tests use it to change the filesystem between steps.
type pinFunc func(projectRoot, name string, step func(string)) (pinnedConfig, error)

// checkPinnablePath rejects record paths that a pinned walk cannot take literally: relative
// or uncleaned paths (".." components) and config names that are not a single component.
func checkPinnablePath(projectRoot, name string) error {
	if !filepath.IsAbs(projectRoot) || filepath.Clean(projectRoot) != projectRoot {
		return fmt.Errorf("trust record path must be absolute and clean: %s", projectRoot)
	}
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("trust record config name must be a single path component: %q", name)
	}
	return nil
}

// statOwnedFile reads the identity of an open handle and closes it.
func statOwnedFile(file *os.File) (os.FileInfo, error) {
	defer file.Close()
	return file.Stat()
}
