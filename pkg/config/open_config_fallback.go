//go:build !windows && !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package config

import (
	"fmt"
	"os"
)

func openRegularConfigFile(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("configuration file must be a regular file: %s", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	openedInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("configuration file must be a regular file: %s", path)
	}
	return file, nil
}
