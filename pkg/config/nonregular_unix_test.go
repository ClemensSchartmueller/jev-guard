//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package config

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLoadConfigWithPaths_DoesNotBlockOnFIFOProjectConfig(t *testing.T) {
	clearConfigEnvironment(t)

	repo := t.TempDir()
	fifoPath := filepath.Join(repo, ".jevguard.json")
	if err := syscall.Mkfifo(fifoPath, 0600); err != nil {
		t.Skipf("FIFO creation is unavailable on this filesystem: %v", err)
	}
	root := t.TempDir()

	done := make(chan *Config, 1)
	go func() {
		done <- LoadConfigWithPaths([]string{repo}, filepath.Join(root, "user-config.json"), filepath.Join(root, "trust-registry.json"))
	}()
	select {
	case cfg := <-done:
		if cfg.Mode != "enforcing" {
			t.Fatalf("FIFO project config changed mode: got %q", cfg.Mode)
		}
		rejectedAsNonRegular := false
		for _, diagnostic := range cfg.Diagnostics {
			if strings.Contains(diagnostic, fifoPath) && strings.Contains(strings.ToLower(diagnostic), "regular") {
				rejectedAsNonRegular = true
				break
			}
		}
		if !rejectedAsNonRegular {
			t.Fatalf("expected an explicit non-regular-file diagnostic for FIFO, got %v", cfg.Diagnostics)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("config discovery blocked while handling a FIFO project config")
	}
}

func TestInspectProjectConfigRejectsDeviceFiles(t *testing.T) {
	devicePath := "/dev/null"
	if _, err := os.Stat(devicePath); err != nil {
		t.Skipf("device file is unavailable: %v", err)
	}

	info, err := InspectProjectConfig(devicePath)
	if err == nil {
		t.Fatalf("expected a non-regular device file to be rejected, got %#v", info)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "regular") {
		t.Fatalf("expected explicit non-regular-file rejection, got %v", err)
	}
}

func TestOpenRegularConfigFileRejectsFIFOWithoutBlocking(t *testing.T) {
	fifoPath := filepath.Join(t.TempDir(), ".jevguard.json")
	if err := syscall.Mkfifo(fifoPath, 0600); err != nil {
		t.Skipf("FIFO creation is unavailable on this filesystem: %v", err)
	}
	assertSafeConfigOpenRejectsPromptly(t, fifoPath)
}

func TestOpenRegularConfigFileRejectsDevice(t *testing.T) {
	devicePath := "/dev/null"
	if _, err := os.Stat(devicePath); err != nil {
		t.Skipf("device file is unavailable: %v", err)
	}
	assertSafeConfigOpenRejectsPromptly(t, devicePath)
}

func assertSafeConfigOpenRejectsPromptly(t *testing.T, path string) {
	t.Helper()
	type result struct {
		file *os.File
		err  error
	}
	done := make(chan result, 1)
	go func() {
		file, err := openRegularConfigFile(path)
		done <- result{file: file, err: err}
	}()
	select {
	case result := <-done:
		if result.file != nil {
			_ = result.file.Close()
		}
		if result.err == nil {
			t.Fatalf("safe config open accepted non-regular path %s", path)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("safe config open blocked on non-regular path %s", path)
	}
}
