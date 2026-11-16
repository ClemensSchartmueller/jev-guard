package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// trustPinningSupported reports whether this platform can pin a trust record's path without
// a separate, raceable path resolution. Without it, canonical records never apply.
const trustPinningSupported = true

const (
	// fileReadAttributes is FILE_READ_ATTRIBUTES, enough to read a handle's identity and
	// final path without read access to the file's contents.
	fileReadAttributes = 0x80
	// pinShareMode omits FILE_SHARE_DELETE, so a directory or file cannot be renamed or
	// deleted while it is held.
	pinShareMode = syscall.FILE_SHARE_READ | syscall.FILE_SHARE_WRITE
)

var procGetFinalPathNameByHandleW = syscall.NewLazyDLL("kernel32.dll").NewProc("GetFinalPathNameByHandleW")

// pinnedHandle is an open handle with the identity and final path read from it.
type pinnedHandle struct {
	file  *os.File
	info  os.FileInfo
	final string
}

// pinRecordedConfig opens a canonical trust record's directory and config file with
// FILE_FLAG_OPEN_REPARSE_POINT, rejects reparse points (symlinks, junctions, mount points),
// and requires the final path that Windows reports for each open handle to equal the
// recorded path, ignoring case. The final path is derived from the handle, not from a
// second lookup, so a junction or symlink anywhere in the path, or a subst or mapped drive,
// makes the comparison fail even if it is swapped back afterwards. The directory handle is
// held without FILE_SHARE_DELETE while the file is opened, so it cannot be renamed between
// the two steps.
func pinRecordedConfig(projectRoot, name string, step func(string)) (pinnedConfig, error) {
	if err := checkPinnablePath(projectRoot, name); err != nil {
		return pinnedConfig{}, err
	}
	step(projectRoot)
	dir, err := openPinnedHandle(projectRoot, fileReadAttributes, syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT, true)
	if err != nil {
		return pinnedConfig{}, err
	}
	defer dir.file.Close()
	if !strings.EqualFold(dir.final, projectRoot) {
		return pinnedConfig{}, fmt.Errorf("%s resolves to %s; the path goes through a link or another name", projectRoot, dir.final)
	}
	configPath := filepath.Join(projectRoot, name)
	step(configPath)
	file, err := openPinnedHandle(configPath, fileReadAttributes, syscall.FILE_FLAG_OPEN_REPARSE_POINT, false)
	if err != nil {
		return pinnedConfig{}, err
	}
	defer file.file.Close()
	if !strings.EqualFold(file.final, configPath) {
		return pinnedConfig{}, fmt.Errorf("%s resolves to %s; the path goes through a link or another name", configPath, file.final)
	}
	return pinnedConfig{dir: dir.info, file: file.info}, nil
}

// openInspectedConfig opens the inspected project directory, following links because the
// inspected spelling may legitimately use them, and holds it without FILE_SHARE_DELETE. It
// then opens the config file for reading without following a final reparse point. Windows
// has no openat in the syscall package, so the file is opened by its full path; what binds
// it to the directory is the final path Windows reports for each handle: the file's must
// lie directly in the directory's, read both before and after the file is opened. The
// returned file is the one whose bytes are hashed. The caller owns file.
func openInspectedConfig(projectRoot, name string, step func(string)) (*os.File, os.FileInfo, error) {
	if err := checkPinnablePath(projectRoot, name); err != nil {
		return nil, nil, err
	}
	step(projectRoot)
	dir, err := openPinnedHandle(projectRoot, fileReadAttributes, syscall.FILE_FLAG_BACKUP_SEMANTICS, true)
	if err != nil {
		return nil, nil, err
	}
	defer dir.file.Close()
	configPath := filepath.Join(projectRoot, name)
	step(configPath)
	file, err := openPinnedHandle(configPath, syscall.GENERIC_READ|fileReadAttributes, syscall.FILE_FLAG_OPEN_REPARSE_POINT, false)
	if err != nil {
		return nil, nil, err
	}
	dirAfter, err := finalPathName(syscall.Handle(dir.file.Fd()))
	if err != nil {
		_ = file.file.Close()
		return nil, nil, err
	}
	if !strings.EqualFold(filepath.Dir(file.final), dir.final) || !strings.EqualFold(dirAfter, dir.final) {
		_ = file.file.Close()
		return nil, nil, fmt.Errorf("%s is not inside %s", file.final, dir.final)
	}
	return file.file, dir.info, nil
}

func openPinnedHandle(path string, access, flags uint32, wantDir bool) (pinnedHandle, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return pinnedHandle{}, err
	}
	handle, err := syscall.CreateFile(name, access, pinShareMode, nil, syscall.OPEN_EXISTING, flags, 0)
	if err != nil {
		return pinnedHandle{}, err
	}
	fail := func(err error) (pinnedHandle, error) {
		_ = syscall.CloseHandle(handle)
		return pinnedHandle{}, err
	}
	if fileType, err := syscall.GetFileType(handle); err != nil || fileType != syscall.FILE_TYPE_DISK {
		return fail(fmt.Errorf("%s is not a disk file or directory", path))
	}
	var attrs syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &attrs); err != nil {
		return fail(err)
	}
	if attrs.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fail(fmt.Errorf("%s is a reparse point", path))
	}
	if isDir := attrs.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY != 0; isDir != wantDir {
		return fail(fmt.Errorf("%s has the wrong file type", path))
	}
	final, err := finalPathName(handle)
	if err != nil {
		return fail(err)
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		return fail(fmt.Errorf("open %s: invalid file handle", path))
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return pinnedHandle{}, err
	}
	if wantDir != info.IsDir() || (!wantDir && !info.Mode().IsRegular()) {
		_ = file.Close()
		return pinnedHandle{}, fmt.Errorf("%s has the wrong file type", path)
	}
	return pinnedHandle{file: file, info: info, final: final}, nil
}

// finalPathName returns GetFinalPathNameByHandleW(FILE_NAME_NORMALIZED | VOLUME_NAME_DOS)
// for handle, without the \\?\ prefix.
func finalPathName(handle syscall.Handle) (string, error) {
	buf := make([]uint16, syscall.MAX_PATH)
	for {
		n, _, callErr := procGetFinalPathNameByHandleW.Call(uintptr(handle), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0)
		if n == 0 {
			return "", fmt.Errorf("GetFinalPathNameByHandle: %w", callErr)
		}
		if int(n) < len(buf) {
			path := syscall.UTF16ToString(buf[:n])
			if strings.HasPrefix(path, `\\?\UNC\`) {
				return `\\` + path[len(`\\?\UNC\`):], nil
			}
			return strings.TrimPrefix(path, `\\?\`), nil
		}
		buf = make([]uint16, n)
	}
}
