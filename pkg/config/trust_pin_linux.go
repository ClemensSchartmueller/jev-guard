package config

import "syscall"

// linuxOPath is O_PATH (Linux 2.6.39+), which the syscall package does not export. It has
// the same value on every architecture Go supports. An O_PATH handle needs only search
// permission on a directory and never opens a device or FIFO for reading.
const linuxOPath = 0x200000

const (
	pinDirFlags  = linuxOPath | syscall.O_DIRECTORY | syscall.O_CLOEXEC
	pinFileFlags = linuxOPath | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
)

func pinOpenat(dirfd int, name string, flags int) (int, error) {
	return syscall.Openat(dirfd, name, flags, 0)
}
