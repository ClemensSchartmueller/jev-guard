//go:build linux || freebsd

package config

import (
	"fmt"
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
