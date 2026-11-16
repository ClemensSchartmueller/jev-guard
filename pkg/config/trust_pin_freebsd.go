package config

import (
	"syscall"
	"unsafe"
)

// freebsdOPath is O_PATH (FreeBSD 13+), which the syscall package does not export. On a
// kernel without it the opens below behave like O_RDONLY, which needs read permission on
// each directory and otherwise fails closed.
const freebsdOPath = 0x00400000

const (
	pinDirFlags  = freebsdOPath | syscall.O_DIRECTORY | syscall.O_CLOEXEC
	pinFileFlags = freebsdOPath | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
)

// pinOpenat calls openat(2) directly; the FreeBSD syscall package has no exported wrapper.
func pinOpenat(dirfd int, name string, flags int) (int, error) {
	path, err := syscall.BytePtrFromString(name)
	if err != nil {
		return -1, err
	}
	fd, _, errno := syscall.Syscall6(syscall.SYS_OPENAT, uintptr(dirfd), uintptr(unsafe.Pointer(path)), uintptr(flags), 0, 0, 0)
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}
