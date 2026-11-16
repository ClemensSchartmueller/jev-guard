package config

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// trustPinningSupported reports whether this platform can pin a trust record's path without
// a separate, raceable path resolution. Without it, canonical records never apply.
const trustPinningSupported = true

// darwinONoFollowAny is O_NOFOLLOW_ANY (macOS 11+, the minimum Go 1.23 supports), which the
// syscall package does not export. open(2) fails if any component of the path, not only
// the last, is a symlink, and the kernel checks this during its single path resolution.
const darwinONoFollowAny = 0x20000000

// pinRecordedConfig opens a canonical trust record's directory and config file with
// O_NOFOLLOW_ANY, so neither path may contain a symlink at the moment it is resolved, and
// returns the identities of both handles. The Go 1.23 syscall package has no openat on
// macOS, so the file is resolved by its full path rather than relative to the directory
// handle; each resolution is still link-free on its own.
func pinRecordedConfig(projectRoot, name string, step func(string)) (pinnedConfig, error) {
	if err := checkPinnablePath(projectRoot, name); err != nil {
		return pinnedConfig{}, err
	}
	return pinDarwinConfig(projectRoot, name, darwinONoFollowAny, step)
}

// pinInspectedConfig opens the inspected project directory, following links because the
// inspected spelling may legitimately use them, and the config file without following a
// final link. Without openat the file is a second lookup of the same spelling.
func pinInspectedConfig(projectRoot, name string, step func(string)) (pinnedConfig, error) {
	if err := checkPinnablePath(projectRoot, name); err != nil {
		return pinnedConfig{}, err
	}
	return pinDarwinConfig(projectRoot, name, 0, step)
}

func pinDarwinConfig(projectRoot, name string, extra int, step func(string)) (pinnedConfig, error) {
	step(projectRoot)
	dirInfo, err := pinDarwinOpen(projectRoot, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|extra)
	if err != nil {
		return pinnedConfig{}, err
	}
	if !dirInfo.IsDir() {
		return pinnedConfig{}, fmt.Errorf("%s is not a directory", projectRoot)
	}
	configPath := filepath.Join(projectRoot, name)
	step(configPath)
	fileInfo, err := pinDarwinOpen(configPath, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC|extra)
	if err != nil {
		return pinnedConfig{}, err
	}
	if !fileInfo.Mode().IsRegular() {
		return pinnedConfig{}, fmt.Errorf("%s is not a regular, non-symlink file", configPath)
	}
	return pinnedConfig{dir: dirInfo, file: fileInfo}, nil
}

func pinDarwinOpen(path string, flags int) (os.FileInfo, error) {
	fd, err := syscall.Open(path, flags, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("open %s: invalid file descriptor", path)
	}
	return statOwnedFile(file)
}
