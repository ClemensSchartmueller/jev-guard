package config

import (
	"syscall"
	_ "unsafe" // for go:linkname
)

// trustPinningSupported reports whether this platform can pin a trust record's path without
// a separate, raceable path resolution. Without it, canonical records never apply.
const trustPinningSupported = true

// darwinONoFollowAny is O_NOFOLLOW_ANY (macOS 11+, the minimum Go 1.23 supports), which the
// syscall package does not export. open(2) fails if any component of the path, not only
// the last, is a symlink, and the kernel checks this during its single path resolution.
const darwinONoFollowAny = 0x20000000

const (
	// macOS has no O_PATH, so directories are opened for reading. A directory without read
	// permission therefore cannot be pinned, which fails closed.
	pinDirFlags  = syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_CLOEXEC
	pinFileFlags = syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
)

// darwinOpenat is the syscall package's unexported openat(2) wrapper, a libc trampoline in
// the standard library. The syscall package marks it with a push go:linkname ("used by
// internal/syscall/unix"), which is what lets the Go 1.23 linker resolve this reference
// without cgo or golang.org/x/sys. If a later Go release withdraws it, the build fails at
// link time rather than silently losing the directory binding.
//
//go:linkname darwinOpenat syscall.openat
func darwinOpenat(fd int, path string, flags int, perm uint32) (int, error)

func pinOpenat(dirfd int, name string, flags int) (int, error) {
	return darwinOpenat(dirfd, name, flags, 0)
}

// pinRecordedConfig opens a canonical trust record's directory with O_NOFOLLOW_ANY, so no
// component of its path may be a symlink at the moment the kernel resolves it, and then
// opens the config file relative to that directory handle without following a link. It
// returns the identities of both handles.
func pinRecordedConfig(projectRoot, name string, step func(string)) (pinnedConfig, error) {
	if err := checkPinnablePath(projectRoot, name); err != nil {
		return pinnedConfig{}, err
	}
	step(projectRoot)
	fd, err := syscall.Open(projectRoot, pinDirFlags|darwinONoFollowAny, 0)
	if err != nil {
		return pinnedConfig{}, err
	}
	return pinConfigInDir(fd, projectRoot, name, step)
}
