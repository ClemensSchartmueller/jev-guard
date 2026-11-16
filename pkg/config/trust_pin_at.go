//go:build linux || freebsd || darwin

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// inspectFileFlags opens the inspected config for reading, without following a final link
// and without blocking on a FIFO.
const inspectFileFlags = syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC

// openInspectedConfig opens the inspected project directory, following links because the
// inspected spelling may legitimately use them, and then opens the config file relative to
// that directory handle (openat) without following a final link. The returned file is the
// one whose bytes are hashed, and dir is the identity of the handle it was opened from, so
// the file is bound to the directory by the kernel's lookup of a single name in that
// directory: switching a link in the inspected spelling between the two steps cannot pair
// one directory with a file found in another. The caller owns file.
func openInspectedConfig(projectRoot, name string, step func(string)) (file *os.File, dir os.FileInfo, err error) {
	if err := checkPinnablePath(projectRoot, name); err != nil {
		return nil, nil, err
	}
	step(projectRoot)
	dirfd, err := syscall.Open(projectRoot, pinDirFlags, 0)
	if err != nil {
		return nil, nil, err
	}
	dirFile := os.NewFile(uintptr(dirfd), projectRoot)
	if dirFile == nil {
		_ = syscall.Close(dirfd)
		return nil, nil, fmt.Errorf("open %s: invalid file descriptor", projectRoot)
	}
	defer dirFile.Close()
	dirInfo, err := dirFile.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !dirInfo.IsDir() {
		return nil, nil, fmt.Errorf("%s is not a directory", projectRoot)
	}
	configPath := filepath.Join(projectRoot, name)
	step(configPath)
	fd, err := pinOpenat(dirfd, name, inspectFileFlags)
	if err != nil {
		return nil, nil, err
	}
	file = os.NewFile(uintptr(fd), configPath)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, nil, fmt.Errorf("open %s: invalid file descriptor", configPath)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, fmt.Errorf("%s is not a regular, non-symlink file", configPath)
	}
	return file, dirInfo, nil
}

// pinConfigInDir opens the config file relative to dirfd without following a link and
// returns the identities of both handles. It takes ownership of dirfd.
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
