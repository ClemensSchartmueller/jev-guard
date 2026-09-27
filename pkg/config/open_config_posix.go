//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package config

import (
	"fmt"
	"os"
	"syscall"
)

func openRegularConfigFile(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("open configuration file %s: invalid file descriptor", path)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("configuration file must be a regular file: %s", path)
	}
	return file, nil
}
