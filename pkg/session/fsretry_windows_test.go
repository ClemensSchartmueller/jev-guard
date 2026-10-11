//go:build windows

package session

import (
	"errors"
	"fmt"
	"io/fs"
	"syscall"
	"testing"
)

func TestIsTransientFSError_Windows(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{syscall.Errno(5), true},
		{syscall.Errno(32), true},
		{syscall.Errno(33), true},
		{&fs.PathError{Op: "open", Path: "x", Err: syscall.Errno(32)}, true},
		{fmt.Errorf("wrapped: %w", &fs.PathError{Op: "rename", Path: "x", Err: syscall.Errno(5)}), true},
		{syscall.Errno(2), false},  // ERROR_FILE_NOT_FOUND
		{syscall.Errno(17), false}, // ERROR_NOT_SAME_DEVICE
		{errors.New("other"), false},
		{nil, false},
	}
	for _, c := range cases {
		if got := isTransientFSError(c.err); got != c.want {
			t.Errorf("isTransientFSError(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}
