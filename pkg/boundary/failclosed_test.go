package boundary

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Windows does not collapse "." and ".." in extended-length and device namespace paths, so
// those are refused instead of cleaned. The classification is lexical and tested on every OS.
func TestHasNamespaceDotComponent(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
	}{
		{`\\?\C:\ws\link\..\file`, true},
		{`\\?\C:\ws\.\file`, true},
		{`\\?\C:\ws\..`, true},
		{`\\?\UNC\srv\share\ws\link\..\f`, true},
		{`\\.\C:\ws\..\f`, true},
		{`\??\C:\ws\..\f`, true},
		{`//?/C:/ws/link/../file`, true},
		{`//./C:/ws/./f`, true},
		{`\\?/C:/ws/../f`, true},
		{`\\?\C:\ws\file`, false},
		{`\\?\C:\ws\..file\f..`, false},
		{`\\?\UNC\srv\share\ws\f`, false},
		{`C:\ws\link\..\file`, false}, // ordinary Win32 path: cleaned as the OS does
		{`\\srv\share\..\f`, false},
		{`/ws/link/../file`, false},
		{`\\?`, false},
	} {
		if got := hasNamespaceDotComponent(c.in); got != c.want {
			t.Errorf("hasNamespaceDotComponent(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	if !errors.Is(ErrUnverifiablePath, ErrResolutionLimit) {
		t.Error("ErrUnverifiablePath must match ErrResolutionLimit so callers fail closed")
	}
}

// In non-strict mode only a name that does not exist is taken as one to be created. Any
// other lookup failure leaves the path unverifiable: not contained, with an error.
func TestNonStrictLookupErrorsAreUnverifiable(t *testing.T) {
	ws := realTempDir(t)
	bad := filepath.Join(ws, "bad")
	orig := lstat
	t.Cleanup(func() { lstat = orig })
	resolver, err := NewResolver([]string{ws}, ws)
	if err != nil {
		t.Fatal(err)
	}
	for _, injected := range []error{syscall.EACCES, syscall.ELOOP, syscall.ENOTDIR, syscall.ENAMETOOLONG, os.ErrNotExist} {
		lstat = func(p string) (os.FileInfo, error) {
			if p == bad {
				return nil, &os.PathError{Op: "lstat", Path: p, Err: injected}
			}
			return orig(p)
		}
		contained, err := resolver.IsPathContained(filepath.Join(bad, "x"), ws)
		switch {
		case errors.Is(injected, os.ErrNotExist):
			if !contained || err != nil {
				t.Errorf("%v: contained=%v err=%v, want a name to be created inside", injected, contained, err)
			}
		case errors.Is(injected, syscall.ENAMETOOLONG):
			if contained || !errors.Is(err, ErrResolutionLimit) {
				t.Errorf("%v: contained=%v err=%v, want a resolution limit", injected, contained, err)
			}
		default:
			if contained || err == nil {
				t.Errorf("%v: contained=%v err=%v, want not contained and an error", injected, contained, err)
			}
		}
	}
}

// A failed normalization (Windows FindFirstFile) must not stand in for the on-disk spelling:
// name-too-long is a resolution limit, other errors are returned, and nothing is cached for
// the failed prefix. A fake normBase exercises the Windows code path on every OS.
func TestNormalizationErrorsFailClosed(t *testing.T) {
	ws := realTempDir(t)
	orig := normBase
	t.Cleanup(func() { normBase = orig })
	for _, injected := range []error{syscall.ENAMETOOLONG, syscall.EACCES, syscall.ELOOP, syscall.ENOTDIR} {
		e := newEvaluation()
		normBase = func(p string) (string, error) {
			return "", &os.PathError{Op: "FindFirstFile", Path: p, Err: injected}
		}
		for _, strict := range []bool{true, false} {
			got, err := e.resolve(ws, strict)
			if err == nil {
				t.Errorf("%v strict=%v: got %q, want an error", injected, strict, got)
			}
			if limit := errors.Is(err, ErrResolutionLimit); limit != errors.Is(injected, syscall.ENAMETOOLONG) {
				t.Errorf("%v strict=%v: err=%v, resolution limit=%v", injected, strict, err, limit)
			}
		}
		normBase = func(p string) (string, error) { return strings.ToUpper(filepath.Base(p)), nil }
		got, err := e.resolve(ws, true)
		if err != nil {
			t.Fatalf("%v: after recovery: %v", injected, err)
		}
		if base := filepath.Base(got); base != strings.ToUpper(filepath.Base(ws)) {
			t.Errorf("%v: a failed normalization was cached: got %q", injected, got)
		}
	}
}
