package boundary

import (
	"errors"
	"syscall"
)

// defaultNormBase is filepath's normBase: the on-disk name of the last component of path.
var defaultNormBase = func(path string) (string, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	var data syscall.Win32finddata
	h, err := syscall.FindFirstFile(p, &data)
	if err != nil {
		return "", err
	}
	syscall.FindClose(h)
	return syscall.UTF16ToString(data.FileName[:]), nil
}

// errorFilenameExcedRange is ERROR_FILENAME_EXCED_RANGE.
const errorFilenameExcedRange = syscall.Errno(206)

func isWindowsNameTooLong(err error) bool {
	return errors.Is(err, errorFilenameExcedRange)
}
