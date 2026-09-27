//go:build windows

package config

import (
	"fmt"
	"os"
	"syscall"
)

func openRegularConfigFile(path string) (*os.File, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(
		name,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	closeOnError := func(err error) (*os.File, error) {
		_ = syscall.CloseHandle(handle)
		return nil, err
	}
	fileType, err := syscall.GetFileType(handle)
	if err != nil {
		return closeOnError(err)
	}
	if fileType != syscall.FILE_TYPE_DISK {
		return closeOnError(fmt.Errorf("configuration file must be a disk file: %s", path))
	}
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &info); err != nil {
		return closeOnError(err)
	}
	if info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return closeOnError(fmt.Errorf("configuration file cannot be a reparse point: %s", path))
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		return closeOnError(fmt.Errorf("open configuration file %s: invalid file handle", path))
	}
	fileInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !fileInfo.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("configuration file must be a regular file: %s", path)
	}
	return file, nil
}
