//go:build linux || freebsd

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// trustPinningSupported reports whether this platform can pin a trust record's path without
// a separate, raceable path resolution. Without it, canonical records never apply.
const trustPinningSupported = true

// pinRecordedConfig opens a canonical trust record's directory one component at a time,
// starting at "/", each component relative to the handle of its parent with O_NOFOLLOW and
// O_DIRECTORY, so no component can be a symlink and no component can be swapped between
// steps. It then opens the config file relative to the final handle, again without
// following a link, and returns the identities of both handles.
func pinRecordedConfig(projectRoot, name string, step func(string)) (pinnedConfig, error) {
	if err := checkPinnablePath(projectRoot, name); err != nil {
		return pinnedConfig{}, err
	}
	step("/")
	fd, err := syscall.Open("/", pinDirFlags, 0)
	if err != nil {
		return pinnedConfig{}, err
	}
	prefix := "/"
	for _, component := range strings.Split(strings.TrimPrefix(projectRoot, "/"), "/") {
		if component == "" {
			continue
		}
		prefix = filepath.Join(prefix, component)
		step(prefix)
		next, err := pinOpenat(fd, component, pinDirFlags|syscall.O_NOFOLLOW)
		_ = syscall.Close(fd)
		if err != nil {
			return pinnedConfig{}, fmt.Errorf("%s is not a directory reached without a symlink: %w", prefix, err)
		}
		fd = next
	}
	return pinConfigInDir(fd, projectRoot, name, step)
}

// pinInspectedConfig opens the inspected project directory, following links because the
// inspected spelling may legitimately use them, and the config file relative to that handle
// without following a link. It proves which directory holds the inspected file under its name.
func pinInspectedConfig(projectRoot, name string, step func(string)) (pinnedConfig, error) {
	if err := checkPinnablePath(projectRoot, name); err != nil {
		return pinnedConfig{}, err
	}
	step(projectRoot)
	fd, err := syscall.Open(projectRoot, pinDirFlags, 0)
	if err != nil {
		return pinnedConfig{}, err
	}
	return pinConfigInDir(fd, projectRoot, name, step)
}

// pinConfigInDir takes ownership of dirfd.
func pinConfigInDir(dirfd int, dirPath, name string, step func(string)) (pinnedConfig, error) {
	dir := os.NewFile(uintptr(dirfd), dirPath)
	if dir == nil {
		_ = syscall.Close(dirfd)
		return pinnedConfig{}, fmt.Errorf("open %s: invalid file descriptor", dirPath)
	}
	defer dir.Close()
	dirInfo, err := dir.Stat()
	if err != nil {
		return pinnedConfig{}, err
	}
	if !dirInfo.IsDir() {
		return pinnedConfig{}, fmt.Errorf("%s is not a directory", dirPath)
	}
	configPath := filepath.Join(dirPath, name)
	step(configPath)
	fd, err := pinOpenat(dirfd, name, pinFileFlags)
	if err != nil {
		return pinnedConfig{}, err
	}
	file := os.NewFile(uintptr(fd), configPath)
	if file == nil {
		_ = syscall.Close(fd)
		return pinnedConfig{}, fmt.Errorf("open %s: invalid file descriptor", configPath)
	}
	fileInfo, err := statOwnedFile(file)
	if err != nil {
		return pinnedConfig{}, err
	}
	if !fileInfo.Mode().IsRegular() {
		return pinnedConfig{}, fmt.Errorf("%s is not a regular, non-symlink file", configPath)
	}
	return pinnedConfig{dir: dirInfo, file: fileInfo}, nil
}
