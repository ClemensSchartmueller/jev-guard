package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
	// pinDirAccess adds FILE_TRAVERSE to fileReadAttributes for directory handles that a
	// config file is opened relative to.
	pinDirAccess = fileReadAttributes | 0x20
	// fileGenericRead is FILE_GENERIC_READ, for the inspected config whose bytes are read.
	fileGenericRead = 0x120089
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

// pinRecordedConfig opens a canonical trust record's directory with
// FILE_FLAG_OPEN_REPARSE_POINT, rejects reparse points (symlinks, junctions, mount points),
// and requires the final path that Windows reports for the open handle to equal the
// recorded path exactly (ordinal, case-sensitive). The final path is derived from the
// handle, not from a second lookup, so a junction or symlink anywhere in the path, or a
// subst or mapped drive, makes the comparison fail even if it is swapped back afterwards.
// The comparison is not case-insensitive because a directory can be case-sensitive (per
// directory, as WSL uses), so names that differ only in case can be different directories;
// GetFinalPathNameByHandle reports the on-disk case, and config trust proposes exactly that
// spelling (resolveTrustProposalRoot). The config file is then opened relative to the held
// directory handle (NtCreateFile with RootDirectory) without following a reparse point, so
// it is bound to that directory by the kernel's lookup of a single name in it.
func pinRecordedConfig(projectRoot, name string, step func(string)) (pinnedConfig, error) {
	if err := checkPinnablePath(projectRoot, name); err != nil {
		return pinnedConfig{}, err
	}
	step(projectRoot)
	dir, err := openPinnedHandle(projectRoot, pinDirAccess, syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT, true)
	if err != nil {
		return pinnedConfig{}, err
	}
	defer dir.file.Close()
	if dir.final != projectRoot {
		return pinnedConfig{}, fmt.Errorf("%s resolves to %s; the path goes through a link or another name", projectRoot, dir.final)
	}
	configPath := filepath.Join(projectRoot, name)
	step(configPath)
	file, err := openFileInDir(dir.file, name, configPath, fileReadAttributes)
	if err != nil {
		return pinnedConfig{}, err
	}
	fileInfo, err := statOwnedFile(file)
	if err != nil {
		return pinnedConfig{}, err
	}
	return pinnedConfig{dir: dir.info, file: fileInfo}, nil
}

// openInspectedConfig opens the inspected project directory, following links because the
// inspected spelling may legitimately use them, and holds it without FILE_SHARE_DELETE. It
// then opens the config file for reading relative to that directory handle (NtCreateFile
// with RootDirectory), without following a reparse point. The returned file is the one
// whose bytes are hashed, and dir is the identity of the handle it was opened from, so the
// file is bound to the directory by the kernel's lookup of a single name in that
// directory: switching a link in the inspected spelling between the two steps cannot pair
// one directory with a file found in another, whatever the case sensitivity of the
// directories involved. The caller owns file.
func openInspectedConfig(projectRoot, name string, step func(string)) (*os.File, os.FileInfo, error) {
	if err := checkPinnablePath(projectRoot, name); err != nil {
		return nil, nil, err
	}
	step(projectRoot)
	dir, err := openPinnedHandle(projectRoot, pinDirAccess, syscall.FILE_FLAG_BACKUP_SEMANTICS, true)
	if err != nil {
		return nil, nil, err
	}
	defer dir.file.Close()
	configPath := filepath.Join(projectRoot, name)
	step(configPath)
	file, err := openFileInDir(dir.file, name, configPath, fileGenericRead)
	if err != nil {
		return nil, nil, err
	}
	return file, dir.info, nil
}

// resolveTrustProposalRoot returns the directory config trust proposes for a canonical
// record: the final path of a handle opened on dir, following links. It is exactly the
// spelling (including case) that pinRecordedConfig later requires the record's directory
// handle to report.
func resolveTrustProposalRoot(dir string) (string, error) {
	handle, err := openPinnedHandle(dir, fileReadAttributes, syscall.FILE_FLAG_BACKUP_SEMANTICS, true)
	if err != nil {
		return "", err
	}
	_ = handle.file.Close()
	return handle.final, nil
}

// Native API definitions for NtCreateFile, which the syscall package does not wrap.
const (
	objCaseInsensitive         = 0x40
	fileOpen                   = 0x1
	fileSynchronousIONonalert  = 0x20
	fileNonDirectoryFile       = 0x40
	fileOpenReparsePoint       = 0x200000
	ntStatusSuccess            = 0
	maxUnicodeStringByteLength = 0xfffe
)

type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type objectAttributes struct {
	Length                   uint32
	RootDirectory            syscall.Handle
	ObjectName               *unicodeString
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type ioStatusBlock struct {
	Status      uintptr
	Information uintptr
}

// ntdll.dll is a KnownDLL, so it is always loaded from the system directory.
var (
	modntdll                  = syscall.NewLazyDLL("ntdll.dll")
	procNtCreateFile          = modntdll.NewProc("NtCreateFile")
	procRtlNtStatusToDosError = modntdll.NewProc("RtlNtStatusToDosError")
)

// openFileInDir opens name, a single path component, relative to the open directory dir
// with NtCreateFile (OBJECT_ATTRIBUTES.RootDirectory), with FILE_OPEN_REPARSE_POINT so a
// reparse point is opened rather than followed (and then rejected), and
// FILE_NON_DIRECTORY_FILE. The handle is shared like the pinned handles, without
// FILE_SHARE_DELETE. displayPath is used in errors and as the file's name only. The
// returned file must be a regular disk file and is owned by the caller.
func openFileInDir(dir *os.File, name, displayPath string, access uint32) (*os.File, error) {
	if name == "" || strings.ContainsAny(name, `/\:`) {
		return nil, fmt.Errorf("config name must be a single path component: %q", name)
	}
	utf16Name, err := syscall.UTF16FromString(name)
	if err != nil {
		return nil, err
	}
	utf16Name = utf16Name[:len(utf16Name)-1] // drop the NUL terminator
	byteLen := 2 * len(utf16Name)
	if byteLen == 0 || byteLen > maxUnicodeStringByteLength {
		return nil, fmt.Errorf("config name has an invalid length: %q", name)
	}
	objectName := unicodeString{Length: uint16(byteLen), MaximumLength: uint16(byteLen), Buffer: &utf16Name[0]}
	attrs := objectAttributes{
		RootDirectory: syscall.Handle(dir.Fd()),
		ObjectName:    &objectName,
		Attributes:    objCaseInsensitive,
	}
	attrs.Length = uint32(unsafe.Sizeof(attrs))
	var iosb ioStatusBlock
	var handle syscall.Handle
	status, _, _ := procNtCreateFile.Call(
		uintptr(unsafe.Pointer(&handle)),
		uintptr(access|syscall.SYNCHRONIZE),
		uintptr(unsafe.Pointer(&attrs)),
		uintptr(unsafe.Pointer(&iosb)),
		0, // AllocationSize
		0, // FileAttributes
		uintptr(pinShareMode),
		fileOpen,
		fileSynchronousIONonalert|fileNonDirectoryFile|fileOpenReparsePoint,
		0, // EaBuffer
		0, // EaLength
	)
	runtime.KeepAlive(dir)
	runtime.KeepAlive(utf16Name)
	runtime.KeepAlive(&objectName)
	if uint32(status) != ntStatusSuccess {
		errno, _, _ := procRtlNtStatusToDosError.Call(status)
		return nil, &os.PathError{Op: "open", Path: displayPath, Err: syscall.Errno(errno)}
	}
	pinned, err := checkPinnedHandle(handle, displayPath, false)
	if err != nil {
		return nil, err
	}
	return pinned.file, nil
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
	return checkPinnedHandle(handle, path, wantDir)
}

// checkPinnedHandle takes ownership of handle and returns it as a pinnedHandle if it is a
// disk file or directory (as wantDir says) that is not a reparse point; otherwise it closes
// handle.
func checkPinnedHandle(handle syscall.Handle, path string, wantDir bool) (pinnedHandle, error) {
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
